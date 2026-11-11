# Mail Platform :: Rspamd em modo milter para o Postfix (porta 25)
bind_socket = "127.0.0.1:11332";
milter = yes;
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
max_retries = 5;
discard_on_reject = false;
quarantine_on_reject = false;
spam_header = "X-Spam";
reject_message = "Spam message rejected";
