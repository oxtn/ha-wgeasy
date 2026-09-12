from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import slugify

from . import WGEasyConfigEntry
from .api import WGEasyApiError, WGEasyAuthError
from .const import API_VERSION_V14, DOMAIN, ENTITY_ID_PREFIX
from .entity_manager import DynamicPeerEntityManager

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass, entry: WGEasyConfigEntry, async_add_entities):
    coordinator = entry.runtime_data

    # Switch is v15-only; the v14 API uses a different auth scheme.
    # Skip the whole platform for v14 entries so no entities are registered.
    if coordinator.api_version == API_VERSION_V14:
        return

    manager = DynamicPeerEntityManager(
        coordinator=coordinator,
        async_add_entities=async_add_entities,
        create_entities=lambda client: [WGPeerSwitch(coordinator, client, entry)],
    )

    initial_entities = manager.build_initial_entities()
    if initial_entities:
        async_add_entities(initial_entities)

    entry.async_on_unload(coordinator.async_add_listener(manager.handle_coordinator_update))


class WGPeerSwitch(CoordinatorEntity, SwitchEntity):
    """Toggle a WireGuard peer's enabled state via the wg-easy v15 admin API."""

    def __init__(self, coordinator, client, entry):
        super().__init__(coordinator)

        self.client_key = client["publicKey"]
        self.client_name_slug = slugify(client.get("name") or self.client_key[:8])
        self._entry = entry
        self._attr_has_entity_name = True
        self._attr_name = "enabled"
        self._attr_unique_id = f"wg_{self.client_key}_switch_enabled"
        self.entity_id = (
            f"switch.{ENTITY_ID_PREFIX}_{self.client_name_slug}_enabled"
        )
        self._last_pushed_state: tuple[Any, bool] | None = None
        # Optimistic: store pending state while waiting for coordinator refresh
        self._optimistic_is_on: bool | None = None

    def _get_client(self):
        return self.coordinator.peer_map.get(self.client_key)

    @property
    def is_on(self) -> bool | None:
        if self._optimistic_is_on is not None:
            return self._optimistic_is_on
        client = self._get_client()
        if not client:
            return None
        return bool(client.get("enabled"))

    @property
    def available(self) -> bool:
        """Available only when admin credentials are configured."""
        return (
            self._get_client() is not None
            and self.coordinator.last_update_success
            and self.coordinator.supports_toggle
        )

    @property
    def device_info(self):
        client = self._get_client()
        name = client["name"] if client else self.client_key[:8]
        return DeviceInfo(
            identifiers={(DOMAIN, self.client_key)},
            name=name,
            manufacturer="WireGuard",
            model="Peer",
        )

    async def async_turn_on(self, **kwargs) -> None:
        """Enable the WireGuard peer."""
        if not self._get_client():
            return
        self._optimistic_is_on = True
        self.async_write_ha_state()
        try:
            await self.coordinator.async_enable_client(self.client_key)
        except (WGEasyAuthError, WGEasyApiError) as err:
            _LOGGER.error("Failed to enable peer %s: %s", self.client_key[:8], err)
        finally:
            self._optimistic_is_on = None

    async def async_turn_off(self, **kwargs) -> None:
        """Disable the WireGuard peer."""
        if not self._get_client():
            return
        self._optimistic_is_on = False
        self.async_write_ha_state()
        try:
            await self.coordinator.async_disable_client(self.client_key)
        except (WGEasyAuthError, WGEasyApiError) as err:
            _LOGGER.error("Failed to disable peer %s: %s", self.client_key[:8], err)
        finally:
            self._optimistic_is_on = None

    def _handle_coordinator_update(self) -> None:
        """Clear optimistic state on coordinator refresh."""
        self._optimistic_is_on = None
        super()._handle_coordinator_update()

    def async_write_ha_state(self) -> None:
        """Skip redundant state writes when nothing has changed."""
        current_state = (self.is_on, self.available)
        if self._last_pushed_state is not None and current_state == self._last_pushed_state:
            return
        self._last_pushed_state = current_state
        super().async_write_ha_state()
