# A fresh Linux VM

Two things that catch a new Ubuntu VM. Seen on Ubuntu while setting up a Hermes-side agent.

## Install `libatomic1` before the Hermes installer

A fresh Ubuntu image does not ship `libatomic1`, and the Hermes installer needs it. Without it the
installer stops at the `npm install` step and does not say why in plain words. Install it first:

```bash
sudo apt-get update && sudo apt-get install -y libatomic1
```

Then run the Hermes installer again.

## Ask `cello status`, not `systemctl`, whether the daemon is up

`cello-daemon.service` is a oneshot unit. After you run `cello login` by hand, `systemctl is-active
cello-daemon` reads `inactive` even while the daemon is running, so it cannot tell you whether the daemon
is up. Use this instead:

```bash
cello status
```
