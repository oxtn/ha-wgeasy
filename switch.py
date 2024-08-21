from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import PlatformNotReady
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up the WireGuard Easy switchs."""
    server = hass.data[DOMAIN][config_entry.entry_id]

    try:
        clients = await server.get_clients()
    except Exception as exception:
        raise PlatformNotReady from exception

    entities = [ClientSensor(server, client) for client in clients]

    async_add_entities(entities)


class ClientSensor(SwitchEntity):
    def __init__(self, server, client):
        """Initialize the sensor."""
        self._server = server
        self._client = client

        self._attr_name = self._client.name
        self._attr_unique_id = self._client.uid

        self._attributes = {
            "address": self._client.address,
            "transfer_rx": self._client.transfer_rx,
            "transfer_tx": self._client.transfer_tx,
            "created_at": self._client.created_at,
            "updated_at": self._client.updated_at,
            "last_handshake_at": self._client.last_handshake_at,
        }

        self._attr_device_info = DeviceInfo(
            entry_type=DeviceEntryType.SERVICE,
            identifiers={(DOMAIN, self._server.url)},
            name=f"WireGuard Easy ({self._server.url})",
        )

    async def async_update(self):
        try:
            self._client = await self._server.get_client(self._client.uid)
        except Exception as exception:
            raise PlatformNotReady from exception

        self._attr_is_on = self._client.enabled

        self._attributes = {
            "address": self._client.address,
            "transfer_rx": self._client.transfer_rx,
            "transfer_tx": self._client.transfer_tx,
            "created_at": self._client.created_at,
            "updated_at": self._client.updated_at,
            "last_handshake_at": self._client.last_handshake_at,
        }

    async def async_turn_on(self):
        """Turn the entity on."""
        await self._client.enable()

    async def async_turn_off(self):
        """Turn the entity off."""
        await self._client.disable()

    @property
    def is_on(self) -> bool:
        """Return true if device is on."""
        return self._client.enabled

    @property
    def extra_state_attributes(self) -> dict[str, str]:
        """Return attributes for the sensor."""
        return self._attributes
