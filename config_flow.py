"""Config flow for WireGuard Easy integration."""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from wg_easy_api_wrapper import Server

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_PASSWORD, CONF_URL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .const import DEFAULT_URL, DOMAIN

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_URL, default=DEFAULT_URL): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


async def validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the user input allows us to connect.

    Data has the keys from STEP_USER_DATA_SCHEMA with values provided by the user.
    """
    url = data[CONF_URL].strip("/")

    try:
        async with Server(url, data[CONF_PASSWORD]) as server:
            isAuthenticated = await server.is_logged_in()

            if not isAuthenticated:
                raise InvalidAuth
    except InvalidAuth as exception:
        raise InvalidAuth from exception
    except Exception as exception:
        raise CannotConnect from exception

    # Return info that you want to store in the config entry.
    return {"title": url}


class ConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow for WireGuard Easy."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info = await validate_input(self.hass, user_input)
            except CannotConnect:
                errors["base"] = "cannot_connect"
            except InvalidAuth:
                errors["base"] = "invalid_auth"
            except Exception:  # pylint: disable=broad-except
                _LOGGER.exception("Unexpected exception")
                errors["base"] = "unknown"
            else:
                return self.async_create_entry(title=info["title"], data=user_input)

        return self.async_show_form(
            step_id="user", data_schema=STEP_USER_DATA_SCHEMA, errors=errors
        )


class CannotConnect(HomeAssistantError):
    """Error to indicate we cannot connect."""


class InvalidAuth(HomeAssistantError):
    """Error to indicate there is invalid auth."""
