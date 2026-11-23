// AegisMesh wearable viewer: the ring, bracelet and clothing tag as real-time 3D models.
// The models come from scripts/models/build_wearables.py (Blender). Each carries three LED dots
// named Sensor_0..Sensor_2 that light up as taps arrive. Everything is local: the models are
// files in this folder and three.js is vendored under vendor/three.
import * as THREE from "./vendor/three/three.module.min.js";
import { GLTFLoader } from "./vendor/three/GLTFLoader.js";
import { RoomEnvironment } from "./vendor/three/RoomEnvironment.js";
import { OrbitControls } from "./vendor/three/OrbitControls.js";

const TEAL = new THREE.Color(0x2ee6c5);
const RED = new THREE.Color(0xff4d6d);
const AMBER = new THREE.Color(0xffc14d);
const IDLE_GLOW = 0.9;

// How each model is turned to face the camera (radians around X, then Y).
const POSE = {
  ring: { x: 0.5, y: -0.55, size: 2.15 },
  bracelet: { x: 0.55, y: -0.5, size: 2.5 },
  clothing_tag: { x: 0.08, y: -0.38, size: 2.7 },
};

function ringTexture() {
  const size = 128;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = size;
  const ctx = canvas.getContext("2d");
  const g = ctx.createRadialGradient(size / 2, size / 2, size * 0.28, size / 2, size / 2, size / 2);
  g.addColorStop(0, "rgba(255,255,255,0)");
  g.addColorStop(0.55, "rgba(255,255,255,0.95)");
  g.addColorStop(0.72, "rgba(255,255,255,0.35)");
  g.addColorStop(1, "rgba(255,255,255,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, size, size);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function shadowTexture() {
  const size = 256;
  const canvas = document.createElement("canvas");
  canvas.width = canvas.height = size;
  const ctx = canvas.getContext("2d");
  const g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
  g.addColorStop(0, "rgba(0,0,0,0.55)");
  g.addColorStop(0.45, "rgba(0,0,0,0.25)");
  g.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = g;
  ctx.fillRect(0, 0, size, size);
  return new THREE.CanvasTexture(canvas);
}

const easeOutBack = (t) => 1 + 2.2 * Math.pow(t - 1, 3) + 1.2 * Math.pow(t - 1, 2);

/**
 * Mounts a viewer in `host` (a positioned element). Resolves once WebGL is up; rejects when the
 * device has no WebGL so the caller can show the static renders instead.
 */
export async function createWearableViewer(host, { modelBase = "models/" } = {}) {
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.05;
  renderer.setClearColor(0x000000, 0);
  const canvas = renderer.domElement;
  canvas.className = "wear-canvas";
  canvas.setAttribute("aria-label", "3D model of the wearable. Drag to turn it.");
  canvas.setAttribute("role", "img");
  host.prepend(canvas);

  const scene = new THREE.Scene();
  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
  scene.environmentIntensity = 0.85;

  const key = new THREE.DirectionalLight(0xffffff, 1.6);
  key.position.set(-3, 4, 5);
  const rim = new THREE.DirectionalLight(0x5be7ff, 2.2);
  rim.position.set(4, 2, -4);
  const violet = new THREE.DirectionalLight(0x9b6bff, 1.3);
  violet.position.set(-5, -2, -3);
  scene.add(key, rim, violet, new THREE.AmbientLight(0x8090c0, 0.25));

  const camera = new THREE.PerspectiveCamera(30, 1, 0.1, 100);
  camera.position.set(0, 0.25, 7.2);

  const controls = new OrbitControls(camera, canvas);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.enablePan = false;
  controls.enableZoom = false; // the mouse wheel keeps scrolling the page
  controls.target.set(0, -0.22, 0);
  controls.minPolarAngle = 0.35;
  controls.maxPolarAngle = Math.PI - 0.6;
  controls.autoRotate = !reduceMotion;
  controls.autoRotateSpeed = 1.1;
  let resumeTimer = 0;
  controls.addEventListener("start", () => {
    controls.autoRotate = false;
    clearTimeout(resumeTimer);
    host.classList.add("grabbing");
  });
  controls.addEventListener("end", () => {
    host.classList.remove("grabbing");
    if (!reduceMotion) resumeTimer = setTimeout(() => { controls.autoRotate = true; }, 4000);
  });

  const stage = new THREE.Group();
  scene.add(stage);
  const shadow = new THREE.Mesh(
    new THREE.PlaneGeometry(3.4, 3.4),
    new THREE.MeshBasicMaterial({ map: shadowTexture(), transparent: true, depthWrite: false }),
  );
  shadow.rotation.x = -Math.PI / 2;
  shadow.position.y = -1.35;
  scene.add(shadow);

  const rippleMap = ringTexture();
  const ripples = [];
  const loader = new GLTFLoader();
  const cache = new Map();
  let current = null; // { form, root, sensors: [{ mesh, glow, colour }] }
  let swapStart = 0;
  let flashState = null;

  function prepare(form, gltf) {
    const root = gltf.scene;
    const box = new THREE.Box3().setFromObject(root);
    const size = box.getSize(new THREE.Vector3());
    const centre = box.getCenter(new THREE.Vector3());
    const pose = POSE[form] || POSE.ring;
    const scale = pose.size / Math.max(size.x, size.y, size.z);
    const pivot = new THREE.Group();
    root.position.sub(centre);
    pivot.add(root);
    pivot.scale.setScalar(scale);
    pivot.rotation.set(pose.x, pose.y, 0, "XYZ");
    const sensors = [];
    root.traverse((node) => {
      const match = /^Sensor_(\d)$/.exec(node.name);
      if (match && node.isMesh) {
        node.material = node.material.clone();
        node.material.emissive = TEAL.clone();
        node.material.emissiveIntensity = IDLE_GLOW;
        sensors[Number(match[1])] = { mesh: node, glow: 0, colour: TEAL };
      }
    });
    return { form, root: pivot, sensors: sensors.filter(Boolean) };
  }

  async function load(form) {
    if (!cache.has(form)) {
      cache.set(form, loader.loadAsync(`${modelBase}${form}.glb`).then((gltf) => prepare(form, gltf)));
    }
    return cache.get(form);
  }

  let wanted = null;
  async function show(form) {
    wanted = form;
    host.classList.add("loading");
    let model;
    try {
      model = await load(form);
    } catch (error) {
      cache.delete(form);
      host.classList.remove("loading");
      throw error;
    }
    if (wanted !== form) return;
    host.classList.remove("loading");
    if (current) stage.remove(current.root);
    current = model;
    stage.add(model.root);
    swapStart = performance.now();
    wake();
  }

  function sensorWorld(sensor) {
    return sensor.mesh.getWorldPosition(new THREE.Vector3());
  }

  function ripple(at, colour = TEAL, scale = 1) {
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({
      map: rippleMap, color: colour, transparent: true, depthWrite: false, depthTest: false,
      blending: THREE.AdditiveBlending,
    }));
    sprite.position.copy(at);
    sprite.scale.setScalar(0.05);
    sprite.renderOrder = 10;
    scene.add(sprite);
    ripples.push({ sprite, born: performance.now(), life: 650 * scale, reach: 0.9 * scale });
  }

  /** Lights dot `index % 3` and sends a ripple out of it. */
  function pulse(index) {
    if (!current || !current.sensors.length) return;
    const sensor = current.sensors[index % current.sensors.length];
    sensor.glow = 1;
    sensor.colour = TEAL;
    ripple(sensorWorld(sensor));
    wake();
  }

  /** ok: all dots flash teal; no: flash red; sos: strobe teal and red with a wide ripple. */
  function flash(kind) {
    if (!current) return;
    flashState = { kind, born: performance.now() };
    const middle = current.sensors[Math.floor(current.sensors.length / 2)];
    if (middle) {
      const colour = kind === "no" ? RED : kind === "warn" ? AMBER : TEAL;
      ripple(sensorWorld(middle), colour, kind === "sos" ? 2.2 : 1.5);
      if (kind === "sos") setTimeout(() => current && ripple(sensorWorld(middle), RED, 2.6), 260);
    }
    wake();
  }

  function resize() {
    const width = Math.max(1, host.clientWidth);
    const height = Math.max(1, host.clientHeight);
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    wake();
  }
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(host);

  let visible = true;
  let running = false;
  const io = new IntersectionObserver((entries) => {
    visible = entries.some((entry) => entry.isIntersecting);
    wake();
  });
  io.observe(host);
  document.addEventListener("visibilitychange", wake);

  function wake() {
    const shouldRun = visible && !document.hidden;
    if (shouldRun && !running) {
      running = true;
      renderer.setAnimationLoop(frame);
    } else if (!shouldRun && running) {
      running = false;
      renderer.setAnimationLoop(null);
    }
  }

  function frame(now) {
    controls.update();
    if (current) {
      const t = Math.min(1, (now - swapStart) / 520);
      const pop = reduceMotion ? 1 : 0.82 + 0.18 * easeOutBack(t);
      stage.scale.setScalar(pop);
      stage.position.y = reduceMotion ? 0 : Math.sin(now / 1400) * 0.04;

      let flashOn = 0;
      let flashColour = TEAL;
      if (flashState) {
        const age = now - flashState.born;
        const span = flashState.kind === "sos" ? 1800 : 1100;
        if (age > span) flashState = null;
        else {
          const period = flashState.kind === "sos" ? 180 : 260;
          flashOn = Math.floor(age / period) % 2 === 0 ? 1 : 0.15;
          flashColour = flashState.kind === "no" ? RED : flashState.kind === "warn" ? AMBER
            : flashState.kind === "sos" ? (Math.floor(age / 360) % 2 ? RED : TEAL) : TEAL;
        }
      }
      current.sensors.forEach((sensor, i) => {
        sensor.glow *= 0.9;
        const breathe = reduceMotion ? 0 : 0.35 * (0.5 + 0.5 * Math.sin(now / 900 + i * 0.9));
        const material = sensor.mesh.material;
        const level = Math.max(IDLE_GLOW + breathe, sensor.glow * 9, flashOn * 8);
        material.emissive.copy(flashOn ? flashColour : sensor.colour);
        material.color.copy(material.emissive).multiplyScalar(0.4);
        material.emissiveIntensity = level;
      });
    }
    for (let i = ripples.length - 1; i >= 0; i--) {
      const r = ripples[i];
      const k = (now - r.born) / r.life;
      if (k >= 1) {
        scene.remove(r.sprite);
        r.sprite.material.dispose();
        ripples.splice(i, 1);
        continue;
      }
      r.sprite.scale.setScalar(0.05 + r.reach * k);
      r.sprite.material.opacity = (1 - k) * (1 - k);
    }
    renderer.render(scene, camera);
  }

  resize();
  return { show, pulse, flash, renderer };
}
