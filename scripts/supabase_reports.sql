-- Problem reports from the website form (web/report.html). Applied to the Supabase project as
-- the migration "reports_table"; kept here for the record.
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
  app_version text check (char_length(app_version) <= 40),
  -- One-way fingerprint of the sender's address and the date, only for the daily cap below.
  sender text
);

alter table public.reports enable row level security;

create policy "anyone may file a report" on public.reports
  for insert to anon, authenticated with check (true);

-- Column grants: a sender cannot set id, created_at or sender, and cannot read anything.
revoke all on public.reports from anon, authenticated;
grant insert (kind, message, details, contact, app_version) on public.reports to anon, authenticated;

-- Spam limits: 10 reports a day from one address, 500 a day in total (protects the free database).
create function public.reports_cap() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  headers json := nullif(current_setting('request.headers', true), '')::json;
  forwarded text[] := string_to_array(coalesce(headers ->> 'x-forwarded-for', ''), ',');
  -- cf-connecting-ip is set by the gateway and cannot be forged by the sender.
  address text := coalesce(headers ->> 'cf-connecting-ip', headers ->> 'x-real-ip',
                           trim(forwarded[array_length(forwarded, 1)]), '');
begin
  new.sender := encode(sha256(convert_to(address || current_date::text, 'UTF8')), 'hex');
  if (select count(*) from public.reports
      where sender = new.sender and created_at > now() - interval '1 day') >= 10 then
    raise exception 'Too many reports from this address today' using errcode = 'P0001';
  end if;
  if (select count(*) from public.reports where created_at > now() - interval '1 day') >= 500 then
    raise exception 'The report box is full for today' using errcode = 'P0001';
  end if;
  return new;
end;
$$;

revoke all on function public.reports_cap() from public, anon, authenticated;

create trigger reports_cap before insert on public.reports
  for each row execute function public.reports_cap();

create index reports_recent on public.reports (created_at desc);
