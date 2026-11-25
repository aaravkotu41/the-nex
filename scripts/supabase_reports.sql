-- Problem reports from the website form (web/report.html). State of the Supabase project after the
-- migrations "reports_table" and "reports_private_rate_limit"; kept here for the record.
--
-- Anyone may add a report; nobody but the project owner (dashboard or service role) can read,
-- change or delete one: there is deliberately no select, update or delete policy.

create table public.reports (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  kind text not null check (kind in ('bug', 'false_alarm', 'missed', 'other')),
  message text not null check (char_length(message) between 10 and 4000),
  details text check (char_length(details) <= 8000),
  contact text check (char_length(contact) <= 200),
  app_version text check (char_length(app_version) <= 40)
);
create index reports_recent on public.reports (created_at desc);

alter table public.reports enable row level security;
create policy "anyone may file a report" on public.reports
  for insert to anon, authenticated with check (true);

-- Column grants: a sender cannot set id or created_at, and cannot read anything.
revoke all on public.reports from anon, authenticated;
grant insert (kind, message, details, contact, app_version) on public.reports to anon, authenticated;

-- Spam limit: 10 reports in 24 hours from one address, 500 in total. The codes live apart from the
-- reports, are keyed (a plain hash of an IP address can be reversed by trying them all), and are
-- deleted after 24 hours. The key is generated in the database and is in no file.
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table private.report_key (
  only_row boolean primary key default true check (only_row),
  key bytea not null
);
insert into private.report_key (key) values (extensions.gen_random_bytes(32));

create table private.report_senders (
  sender bytea not null,
  at timestamptz not null default now()
);
create index report_senders_lookup on private.report_senders (sender, at);

alter table private.report_key enable row level security;
alter table private.report_senders enable row level security;
revoke all on private.report_key, private.report_senders from public, anon, authenticated;

create function public.reports_cap() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  headers json := nullif(current_setting('request.headers', true), '')::json;
  -- cf-connecting-ip is set by the gateway, which refuses a request that tries to forge it.
  address inet := coalesce(headers ->> 'cf-connecting-ip', headers ->> 'x-real-ip', '0.0.0.0')::inet;
  code bytea;
begin
  if family(address) = 6 then
    address := network(set_masklen(address, 64));  -- one household holds a whole /64
  end if;
  select extensions.hmac(convert_to(host(address), 'UTF8'), k.key, 'sha256') into strict code
    from private.report_key k;
  perform pg_advisory_xact_lock(731200125);  -- simultaneous reports must not slip past the count
  if (select count(*) from private.report_senders s
      where s.sender = code and s.at > now() - interval '24 hours') >= 10 then
    raise exception 'Too many reports from this address today' using errcode = 'P0001';
  end if;
  if (select count(*) from public.reports where created_at > now() - interval '24 hours') >= 500 then
    raise exception 'The report box is full for today' using errcode = 'P0001';
  end if;
  insert into private.report_senders (sender) values (code);
  return new;
end;
$$;
revoke all on function public.reports_cap() from public, anon, authenticated;

create trigger reports_cap before insert on public.reports
  for each row execute function public.reports_cap();

create extension if not exists pg_cron;
select cron.schedule('purge-report-senders', '17 * * * *',
  $$delete from private.report_senders where at < now() - interval '24 hours'$$);
