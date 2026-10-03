# Home Assistant integration

This page wires the bridge to Home Assistant: ring notifications (with
snapshot and an open-the-gate reply button) plus a Lovelace gate button.

Prerequisites on the bridge host (`config.json`):

```json
"mqtt": {
  "enabled": true,
  "host": "IP_DEL_BROKER",
  "port": 1883,
  "topic": "bticino/citofono/ring"
},
"http_bind": "0.0.0.0",
"opener": {
  "enabled": true,
  "entrance": "2",
  "cid": 0,
  "destination": "",
  "timeout": 10.0,
  "token": "SEGRETO_LUNGO_A_CASO"
}
```

Find your `entrance` first (someone at the gate):

```sh
python3 src/bticino_opener.py --probe 1,2,3,4,5,6,7,8,9,20
```

If the panel sends media from a public/cloud address (check the SDP `c=` line
of a saved `INVITE`), set `media_ip` to your public IP or DDNS name and forward
UDP `media_ports` (default `2202-2213`, or `"2202-2203"` for a single pair) to
the bridge host. Otherwise the bridge advertises an unreachable LAN address
and no RTP/RTCP packet ever arrives (`audio_udp=0`, FFmpeg demux timeout).

## 1. Same MQTT broker everywhere

Home Assistant must use the **same** broker as the bridge
(Settings → Devices & services → MQTT). Otherwise the trigger below never
fires even though the bridge logs `MQTT: ring pubblicato`. Debug with:

```sh
mosquitto_sub -h IP_DEL_BROKER -u USER -P 'PASS' -t "bticino/citofono/ring" -v
```

Stale retained messages (e.g. `{"event":"test"}` from `scripts/mqtt_test.py`)
make the template condition fail; clear them with:

```sh
mosquitto_pub -h IP_DEL_BROKER -u USER -P 'PASS' -t "bticino/citofono/ring" -n -r
```

## 2. Snapshot camera (optional)

Add a Generic Camera pointing at the bridge (works on LAN):

* Still image URL: `http://IP_DEL_BRIDGE:8766/snapshot.jpg`

## 3. `rest_command` for the opener

In `configuration.yaml` (bridge LAN IP, never expose `/open` to the internet;
the token is mandatory with `http_bind` on LAN):

```yaml
rest_command:
  apri_cancellino:
    url: "http://IP_DEL_BRIDGE:8766/open?token=SEGRETO_LUNGO_A_CASO"
    method: post
    timeout: 15
```

## 4. Ring automation with snapshot and reply button

```yaml
alias: Notifica Citofono
triggers:
  - trigger: mqtt
    topic: bticino/citofono/ring
conditions:
  - condition: template
    value_template: "{{ trigger.payload_json.event == 'ring' }}"
actions:
  - action: camera.snapshot
    target:
      entity_id: camera.videocitofono
    data:
      filename: /config/www/citofono.jpg
  - action: notify.mobile_app_TUO_TELEFONO
    data:
      title: "Suonano al campanello"
      message: "Chiamata al citofono {{ trigger.payload_json.timestamp }}"
      data:
        tag: citofono
        image: "/local/citofono.jpg"
        actions:
          - action: APRI_CANCELLO
            title: Apri cancellino
          - action: IGNORA
            title: Ignora
            destructive: true
mode: single
```

Notes:

* `topic:` sits directly under the trigger (no `options:` wrapper).
* `tag` and `actions` must be nested inside the inner `data:` block,
  otherwise the buttons never appear.
* `image: /local/...` works while the phone is on home Wi-Fi; from outside
  it needs an externally reachable Home Assistant URL.

## 5. Open-from-notification automation

```yaml
alias: Apri cancellino da notifica
triggers:
  - platform: event
    event_type: mobile_app_notification_action
    event_data:
      action: APRI_CANCELLO
actions:
  - action: rest_command.apri_cancellino
  - action: notify.mobile_app_TUO_TELEFONO
    data:
      title: Cancellino
      message: Comando di apertura inviato
      data:
        tag: citofono
mode: single
```

`IGNORA` needs no automation (it only dismisses). After a press, check
`OPENER: OK` in `listener.log`.

## 6. Lovelace button

Dashboard → Edit → Add card → Button:

```yaml
type: button
name: Cancellino
icon: mdi:gate
tap_action:
  action: call-service
  service: rest_command.apri_cancellino
hold_action:
  action: none
```

## 7. Apple Home gate button

`camera-ffmpeg` cannot host it (`doorbell` is input-only; `switches` only
re-trigger doorbell/motion). Use `homebridge-cmdswitch2`:

```json
{ "accessory": "CmdSwitch2", "name": "Cancellino",
  "on_cmd": "curl -s -X POST http://127.0.0.1:8766/open?token=SEGRETO",
  "off_cmd": "true", "timeout": 5000 }
```

HomeKit forbids the same accessory as trigger and action, so the
momentary (lock-like) behaviour needs a `homebridge-dummy` switch plus two
Home automations: *Cancellino ON → Reset ON*, then *Reset ON → Cancellino OFF
+ Reset OFF*.
