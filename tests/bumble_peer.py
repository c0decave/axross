"""The other end for the over-the-air tests: a Bumble device on a second
stick playing an ordinary Bluetooth device.

    python tests/bumble_peer.py usb:1 sensor    # a BLE sensor
    python tests/bumble_peer.py usb:1 speaker   # a discoverable Classic speaker

* ``sensor`` - advertises "axross-sensor" (flags, name, Battery service,
  manufacturer data 0xFFFF), connectable; GATT: Battery Level (read,
  notify; counts down once a second while subscribed) and a Device
  Information model string.
* ``speaker`` - Classic only, discoverable and connectable as
  "axross-speaker" with the Class of Device of a loudspeaker (0x240414).

Prints ``ready <address>`` when it is on the air and runs until stdin
closes (the test ends it) or it is killed.
"""

from __future__ import annotations

import asyncio
import sys

SENSOR_NAME = "axross-sensor"
SPEAKER_NAME = "axross-speaker"
SPEAKER_CLASS = 0x240414
MODEL = b"axross test sensor"


async def main(transport_name: str, role: str) -> None:
    from bumble.core import AdvertisingData
    from bumble.device import Device, DeviceConfiguration
    from bumble.gatt import (
        GATT_BATTERY_LEVEL_CHARACTERISTIC,
        GATT_BATTERY_SERVICE,
        GATT_DEVICE_INFORMATION_SERVICE,
        GATT_MODEL_NUMBER_STRING_CHARACTERISTIC,
        Characteristic,
        Service,
    )
    from bumble.transport import open_transport

    async with await open_transport(transport_name) as hci:
        if role == "sensor":
            config = DeviceConfiguration(name=SENSOR_NAME, classic_enabled=False,
                                         le_enabled=True)
            device = Device.from_config_with_hci(config, hci.source, hci.sink)
            level = {"value": 90}
            battery = Characteristic(
                GATT_BATTERY_LEVEL_CHARACTERISTIC,
                Characteristic.Properties.READ | Characteristic.Properties.NOTIFY,
                Characteristic.READABLE, bytes([level["value"]]))
            device.add_services([
                Service(GATT_BATTERY_SERVICE, [battery]),
                Service(GATT_DEVICE_INFORMATION_SERVICE, [Characteristic(
                    GATT_MODEL_NUMBER_STRING_CHARACTERISTIC, Characteristic.Properties.READ,
                    Characteristic.READABLE, MODEL)])])
            await device.power_on()
            device.advertising_data = bytes(AdvertisingData([
                (AdvertisingData.FLAGS, bytes([0x06])),
                (AdvertisingData.COMPLETE_LOCAL_NAME, SENSOR_NAME.encode()),
                (AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS, bytes([0x0F, 0x18])),
                (AdvertisingData.MANUFACTURER_SPECIFIC_DATA, bytes([0xFF, 0xFF, 0x01, 0x02]))]))
            await device.start_advertising(auto_restart=True)

            async def tick():
                while True:
                    await asyncio.sleep(1)
                    level["value"] = max(1, level["value"] - 1)
                    battery.value = bytes([level["value"]])
                    await device.notify_subscribers(battery, battery.value)
            asyncio.ensure_future(tick())
        else:
            config = DeviceConfiguration(name=SPEAKER_NAME, classic_enabled=True,
                                         le_enabled=False)
            config.class_of_device = SPEAKER_CLASS
            device = Device.from_config_with_hci(config, hci.source, hci.sink)
            await device.power_on()
            await device.set_discoverable(True)
            await device.set_connectable(True)
        print("ready", str(device.public_address).split("/")[0], flush=True)
        await asyncio.get_running_loop().run_in_executor(None, sys.stdin.read)
        try:
            await device.power_off()
        except Exception:  # noqa: BLE001 - going anyway
            pass


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "sensor"))
