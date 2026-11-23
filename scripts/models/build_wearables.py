"""Builds the AegisMesh wearable models (ring, bracelet, clothing tag) in Blender, exports one
GLB per wearable for the console's 3D viewer and renders a transparent product shot of each.

Run headless from the repository root:

    "C:\\Program Files\\Blender Foundation\\Blender 5.2\\blender.exe" -b --factory-startup ^
        --python scripts/models/build_wearables.py -- --out ui/aegismesh/models

Units are centimetres (1 Blender unit = 1 cm); the viewer rescales each model to fit.
Every wearable carries three LED dots named Sensor_0..Sensor_2: the console lights them one
by one as taps arrive, so the dots mirror the triple-tap rhythm.
"""
import argparse
import math
import os
import sys

import bmesh
import bpy
from mathutils import Matrix, Vector

# ------------------------------------------------------------------ materials

MATERIALS = {
    # name: base colour (linear), metallic, roughness, extra
    "Titanium": ((0.36, 0.38, 0.43), 1.0, 0.22, {}),
    "Ceramic": ((0.012, 0.013, 0.018), 0.0, 0.18, {"coat": 1.0}),
    "Glass": ((0.006, 0.008, 0.016), 0.0, 0.06, {"coat": 1.0}),
    "LED": ((0.10, 0.75, 0.60), 0.0, 0.3, {"emission": (0.10, 0.85, 0.66), "strength": 1.5}),
    "Silicone": ((0.030, 0.040, 0.085), 0.0, 0.55, {}),
    "Aluminium": ((0.55, 0.60, 0.68), 1.0, 0.24, {}),
    "Fabric": ((0.040, 0.050, 0.085), 0.0, 0.92, {}),
    "Thread": ((0.55, 0.60, 0.70), 0.0, 0.75, {}),
    "Weave": ((0.08, 0.62, 0.50), 0.0, 0.6, {"emission": (0.08, 0.62, 0.50), "strength": 0.15}),
}


def principled(material):
    if hasattr(material, "use_nodes"):
        try:
            material.use_nodes = True
        except (AttributeError, TypeError):
            pass
    for node in material.node_tree.nodes:
        if node.type == "BSDF_PRINCIPLED":
            return node
    raise RuntimeError(f"no Principled BSDF in {material.name}")


def make_materials():
    made = {}
    for name, (base, metallic, roughness, extra) in MATERIALS.items():
        material = bpy.data.materials.new(name)
        bsdf = principled(material)
        bsdf.inputs["Base Color"].default_value = (*base, 1.0)
        bsdf.inputs["Metallic"].default_value = metallic
        bsdf.inputs["Roughness"].default_value = roughness
        if "coat" in extra:
            bsdf.inputs["Coat Weight"].default_value = extra["coat"]
            bsdf.inputs["Coat Roughness"].default_value = 0.03
        if "emission" in extra:
            bsdf.inputs["Emission Color"].default_value = (*extra["emission"], 1.0)
            bsdf.inputs["Emission Strength"].default_value = extra["strength"]
        made[name] = material
    return made


# ------------------------------------------------------------------ mesh helpers


def squircle(n_points, half_r, half_z, power=4.0):
    """Closed rounded-rectangle profile (r, z), counter-clockwise from the outer side."""
    pts = []
    for i in range(n_points):
        phi = 2 * math.pi * i / n_points
        c, s = math.cos(phi), math.sin(phi)
        r = half_r * math.copysign(abs(c) ** (2 / power), c)
        z = half_z * math.copysign(abs(s) ** (2 / power), s)
        pts.append((r, z, c))
    return pts


def sweep(name, path, steps, profile, material_for, collection):
    """Sweeps a closed profile along a closed planar path in the XZ plane.

    path(t) -> (centre, outward normal); the profile's second axis runs along +Y.
    material_for(profile_cos) -> material slot index."""
    bm = bmesh.new()
    rings = []
    for i in range(steps):
        centre, normal = path(2 * math.pi * i / steps)
        ring = []
        for r, z, _ in profile:
            ring.append(bm.verts.new(centre + normal * r + Vector((0, z, 0))))
        rings.append(ring)
    n = len(profile)
    for i in range(steps):
        a, b = rings[i], rings[(i + 1) % steps]
        for j in range(n):
            k = (j + 1) % n
            face = bm.faces.new((a[j], a[k], b[k], b[j]))
            face.material_index = material_for((profile[j][2] + profile[k][2]) / 2)
            face.smooth = True
    bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])
    return finish(bm, name, collection)


def rounded_box(size, corner, corner_segments, edge, edge_segments, cuts_x=0):
    """Box centred on the origin with rounded vertical corners and softened top/bottom edges.
    cuts_x adds slices across X so the box can be bent onto a curve."""
    sx, sy, sz = size
    bm = bmesh.new()
    bmesh.ops.create_cube(bm, size=1.0)
    bmesh.ops.scale(bm, vec=(sx, sy, sz), verts=bm.verts[:])
    vertical = [e for e in bm.edges if abs(e.verts[0].co.z - e.verts[1].co.z) > sz * 0.5]
    if corner > 0:
        bmesh.ops.bevel(bm, geom=vertical, offset=corner, offset_type="OFFSET", segments=corner_segments,
                        profile=0.5, affect="EDGES", clamp_overlap=True)
    if edge > 0:
        rim = [e for e in bm.edges
               if all(abs(abs(v.co.z) - sz / 2) < 1e-5 for v in e.verts)
               and abs(e.verts[0].co.z - e.verts[1].co.z) < 1e-6
               and len(e.link_faces) == 2
               and any(abs(f.normal.z) < 0.99 for f in e.link_faces)]
        bmesh.ops.bevel(bm, geom=rim, offset=edge, offset_type="OFFSET", segments=edge_segments,
                        profile=0.5, affect="EDGES", clamp_overlap=True)
    for i in range(1, cuts_x):
        x = -sx / 2 + sx * i / cuts_x
        geom = bm.verts[:] + bm.edges[:] + bm.faces[:]
        bmesh.ops.bisect_plane(bm, geom=geom, dist=1e-6, plane_co=(x, 0, 0), plane_no=(1, 0, 0))
    return bm


def wrap(bm, radius, centre_z, base, down=False):
    """Bends a box built along X around a circle in the XZ plane (local z becomes radial)."""
    for v in bm.verts:
        x, y, z = v.co
        angle = x / radius
        r = radius + base + z
        v.co = Vector((r * math.sin(angle), y, centre_z - r * math.cos(angle) if down else centre_z + r * math.cos(angle)))


def sharpen(bm, degrees=38.0):
    limit = math.radians(degrees)
    for face in bm.faces:
        face.smooth = True
    for edge in bm.edges:
        if len(edge.link_faces) == 2 and edge.calc_face_angle(0.0) > limit:
            edge.smooth = False


def finish(bm, name, collection, material=None):
    mesh = bpy.data.meshes.new(name)
    bm.to_mesh(mesh)
    bm.free()
    obj = bpy.data.objects.new(name, mesh)
    collection.objects.link(obj)
    if material is not None:
        mesh.materials.append(material)
    return obj


def dome(name, radius, flatten, material, collection):
    bm = bmesh.new()
    bmesh.ops.create_uvsphere(bm, u_segments=24, v_segments=12, radius=radius)
    bmesh.ops.scale(bm, vec=(1, 1, flatten), verts=bm.verts[:])
    for face in bm.faces:
        face.smooth = True
    return finish(bm, name, collection, material)


def place_on_arc(obj, radius, centre_z, arc_x, y=0.0, down=False):
    angle = arc_x / radius
    if down:
        obj.location = (radius * math.sin(angle), y, centre_z - radius * math.cos(angle))
        obj.rotation_euler = (0.0, math.pi - angle, 0.0)
    else:
        obj.location = (radius * math.sin(angle), y, centre_z + radius * math.cos(angle))
        obj.rotation_euler = (0.0, angle, 0.0)


def collection_for(name):
    collection = bpy.data.collections.new(name)
    bpy.context.scene.collection.children.link(collection)
    return collection


# ------------------------------------------------------------------ wearables


def build_ring(m):
    col = collection_for("ring")
    inner, thickness, width = 0.90, 0.24, 0.78
    centre_r = inner + thickness / 2
    outer = inner + thickness

    def path(t):
        return Vector((centre_r * math.sin(t), 0, centre_r * math.cos(t))), Vector((math.sin(t), 0, math.cos(t)))

    band = sweep("Band", path, 192, squircle(44, thickness / 2, width / 2, 3.6),
                 lambda c: 0 if c > -0.15 else 1, col)
    band.data.materials.append(m["Titanium"])
    band.data.materials.append(m["Ceramic"])

    # Tap pad: a glass pill set into the top of the band.
    pad_t = 0.05
    bm = rounded_box((0.98, 0.46, pad_t), 0.225, 12, 0.018, 3, cuts_x=24)
    wrap(bm, outer, 0.0, -0.022 + pad_t / 2)
    sharpen(bm)
    finish(bm, "TapPad", col, m["Glass"])

    for i, x in enumerate((-0.24, 0.0, 0.24)):
        dot = dome(f"Sensor_{i}", 0.05, 0.42, m["LED"], col)
        place_on_arc(dot, outer - 0.022 + pad_t, 0.0, x)

    # Optical heart-rate window on the inside, facing the finger.
    for i, y in enumerate((-0.17, 0.17)):
        ppg = dome(f"Optical_{i}", 0.075, 0.34, m["Glass"], col)
        place_on_arc(ppg, inner + 0.004, 0.0, 0.0, y=y, down=True)
    return col


def build_bracelet(m):
    col = collection_for("bracelet")
    a, b, thickness, width = 3.0, 2.45, 0.32, 1.7

    def path(t):
        centre = Vector((a * math.cos(t), 0, b * math.sin(t)))
        normal = Vector((b * math.cos(t), 0, a * math.sin(t))).normalized()
        return centre, normal

    sweep("Band", path, 240, squircle(36, thickness / 2, width / 2, 4.0), lambda c: 0, col).data.materials.append(m["Silicone"])

    crown = a * a / b  # curvature radius at the top and bottom of the ellipse
    top = b + thickness / 2
    module_t = 0.62
    bm = rounded_box((2.5, 1.96, module_t), 0.44, 10, 0.17, 4, cuts_x=26)
    wrap(bm, crown, top - crown, -0.05 + module_t / 2)
    sharpen(bm)
    finish(bm, "Module", col, m["Aluminium"])

    glass_t = 0.06
    glass_base = -0.05 + module_t - 0.025
    bm = rounded_box((2.12, 1.58, glass_t), 0.36, 10, 0.024, 3, cuts_x=22)
    wrap(bm, crown, top - crown, glass_base + glass_t / 2)
    sharpen(bm)
    finish(bm, "Face", col, m["Glass"])

    for i, x in enumerate((-0.34, 0.0, 0.34)):
        dot = dome(f"Sensor_{i}", 0.08, 0.4, m["LED"], col)
        place_on_arc(dot, crown + glass_base + glass_t, top - crown, x)

    bm = rounded_box((1.15, 1.82, 0.24), 0.16, 6, 0.07, 3, cuts_x=12)
    wrap(bm, crown, -top + crown, -0.04 + 0.12, down=True)
    sharpen(bm)
    finish(bm, "Clasp", col, m["Aluminium"])
    return col


SHIELD_OUTER = [(16, 3.5), (26.5, 7), (26, 16.5), (22.5, 23), (16, 28.5), (9.5, 23), (6, 16.5), (5.5, 7)]
SHIELD_INNER = [(16, 7.4), (22.8, 9.7), (22.4, 16.1), (19.8, 20.9), (16, 24.3), (12.2, 20.9), (9.6, 16.1), (9.2, 9.7)]
SHIELD_GEM = [(16, 11.2), (19.3, 15.4), (16, 19.6), (12.7, 15.4)]


def tag_bend(x, bend_r=7.0):
    return x * x / (2 * bend_r)


def bend_bake(obj):
    """Bakes the object's transform into its mesh and makes it follow the label's curve."""
    mesh = obj.data
    mesh.transform(obj.matrix_basis)
    obj.matrix_basis = Matrix.Identity(4)
    for v in mesh.vertices:
        v.co.y += tag_bend(v.co.x)


def build_tag(m):
    col = collection_for("clothing_tag")
    w, h, t = 4.6, 2.5, 0.05
    front = -t / 2

    bm = rounded_box((w, h, t), 0.09, 4, 0.012, 2, cuts_x=40)
    # The box is built flat in XY; stand it up in XZ facing -Y, then curve it gently.
    bmesh.ops.rotate(bm, verts=bm.verts[:], cent=(0, 0, 0), matrix=Matrix.Rotation(math.radians(90), 3, "X"))
    for v in bm.verts:
        v.co.y += tag_bend(v.co.x)
    sharpen(bm)
    finish(bm, "Label", col, m["Fabric"])

    def on_front(obj, x, z, lift=0.0):
        obj.location = (x, front + tag_bend(x) - lift, z)

    # Stitching at both sewn ends and a woven border.
    for side in (-1, 1):
        x = side * (w / 2 - 0.2)
        z = -h / 2 + 0.16
        i = 0
        while z < h / 2 - 0.12:
            bm = rounded_box((0.035, 0.1, 0.03), 0.012, 2, 0.0, 1)
            bmesh.ops.rotate(bm, verts=bm.verts[:], cent=(0, 0, 0), matrix=Matrix.Rotation(math.radians(90), 3, "X"))
            stitch = finish(bm, f"Stitch_{'LR'[side > 0]}{i}", col, m["Thread"])
            on_front(stitch, x, z, 0.004)
            z += 0.17
            i += 1
    for x0, z0, sx, sz in ((0, h / 2 - 0.22, w - 0.95, 0.022), (0, -h / 2 + 0.22, w - 0.95, 0.022)):
        bm = rounded_box((sx, sz, 0.012), 0.008, 2, 0.0, 1, cuts_x=30)
        bmesh.ops.rotate(bm, verts=bm.verts[:], cent=(0, 0, 0), matrix=Matrix.Rotation(math.radians(90), 3, "X"))
        for v in bm.verts:
            v.co.y += tag_bend(v.co.x + x0)
        border = finish(bm, f"Border_{'T' if z0 > 0 else 'B'}", col, m["Thread"])
        border.location = (x0, front - 0.004, z0)

    # Woven AegisMesh shield, in the brand colour.
    scale, cx, cz = 0.04, -1.42, 0.0

    def to_tag(p):
        return Vector(((p[0] - 16) * scale + cx, 0, -(p[1] - 16) * scale + cz))

    bm = bmesh.new()
    outer = [bm.verts.new(to_tag(p)) for p in SHIELD_OUTER]
    inner = [bm.verts.new(to_tag(p)) for p in SHIELD_INNER]
    for i in range(len(outer)):
        j = (i + 1) % len(outer)
        bm.faces.new((outer[i], outer[j], inner[j], inner[i]))
    bm.faces.new([bm.verts.new(to_tag(p)) for p in SHIELD_GEM])
    bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])
    for face in bm.faces:
        if face.normal.y > 0:
            face.normal_flip()
    extruded = bmesh.ops.extrude_face_region(bm, geom=bm.faces[:])
    moved = [g for g in extruded["geom"] if isinstance(g, bmesh.types.BMVert)]
    bmesh.ops.translate(bm, vec=(0, -0.022, 0), verts=moved)
    bmesh.ops.recalc_face_normals(bm, faces=bm.faces[:])
    sharpen(bm, 30)
    logo = finish(bm, "Logo", col, m["Weave"])
    logo.location = (0, front + 0.004, 0)
    bend_bake(logo)

    def text(name, body, size, x, z, material, spacing=1.15):
        curve = bpy.data.curves.new(name, type="FONT")
        curve.body = body
        curve.size = size
        curve.extrude = 0.008
        curve.align_x = "CENTER"
        curve.align_y = "CENTER"
        curve.space_character = spacing
        holder = bpy.data.objects.new(name + "_curve", curve)
        col.objects.link(holder)
        holder.rotation_euler = (math.radians(90), 0, 0)
        bpy.context.view_layer.update()
        depsgraph = bpy.context.evaluated_depsgraph_get()
        mesh = bpy.data.meshes.new_from_object(holder.evaluated_get(depsgraph))
        mesh.transform(holder.matrix_basis)
        bpy.data.objects.remove(holder)
        obj = bpy.data.objects.new(name, mesh)
        col.objects.link(obj)
        mesh.materials.clear()
        mesh.materials.append(material)
        obj.location = (x, front - 0.006, z)
        bend_bake(obj)
        return obj

    text("Wordmark", "AEGISMESH", 0.3, 0.12, 0.16, m["Thread"])
    text("Caption", "SILENT SOS · TAP x3", 0.13, 0.12, -0.24, m["Weave"], 1.2)

    # The tap sensor sits under the fabric: a soft dome with three LED dots on it.
    px = 1.5
    puck = dome("Puck", 0.44, 0.16, m["Fabric"], col)
    puck.rotation_euler = (math.radians(90), 0, 0)
    puck.location = (px, front, 0.0)
    bend_bake(puck)
    for i, dz in enumerate((0.17, 0.0, -0.17)):
        dot = dome(f"Sensor_{i}", 0.045, 0.45, m["LED"], col)
        dot.rotation_euler = (math.radians(90), 0, 0)
        on_front(dot, px, dz, 0.068)
    return col


# ------------------------------------------------------------------ export and render


def select_only(collection):
    bpy.ops.object.select_all(action="DESELECT")
    for obj in collection.objects:
        obj.select_set(True)
    bpy.context.view_layer.objects.active = collection.objects[0]


def export_glb(collection, path):
    select_only(collection)
    bpy.ops.export_scene.gltf(
        filepath=path,
        export_format="GLB",
        use_selection=True,
        export_apply=True,
        export_yup=True,
        export_materials="EXPORT",
        export_cameras=False,
        export_lights=False,
        export_animations=False,
        export_extras=False,
        export_copyright="The Nex / AegisMesh",
    )


def setup_render(width, height):
    scene = bpy.context.scene
    scene.render.engine = "BLENDER_EEVEE"
    scene.render.film_transparent = True
    scene.render.resolution_x = width
    scene.render.resolution_y = height
    scene.render.resolution_percentage = 100
    scene.render.image_settings.file_format = "WEBP"
    scene.render.image_settings.color_mode = "RGBA"
    scene.render.image_settings.quality = 88
    scene.view_settings.view_transform = "AgX"
    scene.view_settings.look = "AgX - Medium High Contrast"
    try:
        scene.eevee.taa_render_samples = 96
    except AttributeError:
        pass

    world = bpy.data.worlds.new("Studio")
    scene.world = world
    tree = world.node_tree
    background = next(n for n in tree.nodes if n.type == "BACKGROUND")
    env = tree.nodes.new("ShaderNodeTexEnvironment")
    hdri = os.path.join(bpy.utils.system_resource("DATAFILES", path="studiolights/world"), "interior.exr")
    env.image = bpy.data.images.load(hdri)
    tree.links.new(env.outputs["Color"], background.inputs["Color"])
    background.inputs["Strength"].default_value = 0.55

    def light(name, kind, energy, colour, location, size=2.0):
        data = bpy.data.lights.new(name, kind)
        data.energy = energy
        data.color = colour
        if kind == "AREA":
            data.size = size
        obj = bpy.data.objects.new(name, data)
        scene.collection.objects.link(obj)
        obj.location = location
        direction = -Vector(location)
        obj.rotation_euler = direction.to_track_quat("-Z", "Y").to_euler()
        return obj

    light("Key", "AREA", 900, (1.0, 0.96, 0.92), (-5, -7, 6), 5)
    light("Rim", "AREA", 1100, (0.45, 0.85, 1.0), (6, 5, 4), 4)
    light("Fill", "AREA", 260, (0.75, 0.70, 1.0), (7, -6, -2), 6)
    light("Top", "AREA", 300, (1.0, 1.0, 1.0), (0, 0, 9), 6)

    cam_data = bpy.data.cameras.new("Camera")
    cam_data.lens = 70
    camera = bpy.data.objects.new("Camera", cam_data)
    scene.collection.objects.link(camera)
    scene.camera = camera
    return camera


def frame(camera, collection, direction):
    corners = []
    for obj in collection.objects:
        corners += [obj.matrix_world @ Vector(c) for c in obj.bound_box]
    low = Vector((min(c.x for c in corners), min(c.y for c in corners), min(c.z for c in corners)))
    high = Vector((max(c.x for c in corners), max(c.y for c in corners), max(c.z for c in corners)))
    centre = (low + high) / 2
    radius = (high - low).length / 2
    fov = 2 * math.atan(18 / camera.data.lens)
    scene = bpy.context.scene
    aspect = scene.render.resolution_y / scene.render.resolution_x
    fit = min(fov, 2 * math.atan(math.tan(fov / 2) * aspect)) if aspect < 1 else fov
    distance = radius / math.sin(fit / 2) * 0.92
    camera.location = centre + direction.normalized() * distance
    camera.rotation_euler = (centre - camera.location).to_track_quat("-Z", "Y").to_euler()


def render(collection, others, camera, path, direction):
    for other in others:
        other.hide_render = True
    collection.hide_render = False
    frame(camera, collection, direction)
    bpy.context.scene.render.filepath = path
    bpy.ops.render.render(write_still=True)


def main():
    argv = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else []
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--no-render", action="store_true")
    args = parser.parse_args(argv)
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)

    bpy.ops.wm.read_factory_settings(use_empty=True)
    materials = make_materials()
    built = {"ring": build_ring(materials), "bracelet": build_bracelet(materials), "clothing_tag": build_tag(materials)}

    for name, collection in built.items():
        export_glb(collection, os.path.join(out, f"{name}.glb"))
        print(f"exported {name}.glb", flush=True)

    if not args.no_render:
        camera = setup_render(720, 540)
        views = {
            "ring": Vector((0.55, -1.0, 0.42)),
            "bracelet": Vector((0.6, -1.0, 0.55)),
            "clothing_tag": Vector((0.42, -1.0, 0.3)),
        }
        for name, collection in built.items():
            others = [c for n, c in built.items() if n != name]
            render(collection, others, camera, os.path.join(out, f"{name}.webp"), views[name])
            print(f"rendered {name}.webp", flush=True)


main()
