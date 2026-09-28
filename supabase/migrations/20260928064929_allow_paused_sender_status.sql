ALTER TABLE public.senders
DROP CONSTRAINT IF EXISTS senders_status_check;

ALTER TABLE public.senders
ADD CONSTRAINT senders_status_check
CHECK (status IN ('active', 'paused', 'dead'));
