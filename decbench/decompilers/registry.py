"""Decompiler plugin registry."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, TypeVar

if TYPE_CHECKING:
    from decbench.decompilers.base import Decompiler, DecompilerConfig

T = TypeVar("T", bound="Decompiler")


class DecompilerRegistry:
    """Registry for decompiler plugins.

    This is a singleton that manages all registered decompilers.

    Usage:
        # Get the registry
        registry = DecompilerRegistry()

        # List available decompilers
        for name in registry.list_available():
            print(name)

        # Get a specific decompiler
        dec = registry.get("angr")
        if dec.is_available():
            result = dec.decompile_binary(binary_path)
    """

    _instance: DecompilerRegistry | None = None
    _decompilers: dict[str, type[Decompiler]] = {}

    def __new__(cls) -> DecompilerRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def register(cls, name: str, decompiler_class: type[Decompiler]) -> None:
        """Register a decompiler class.

        Args:
            name: Unique identifier for the decompiler
            decompiler_class: The decompiler class to register
        """
        cls._decompilers[name] = decompiler_class

    @classmethod
    def get(
        cls,
        name: str,
        config: DecompilerConfig | None = None,
    ) -> Decompiler:
        """Get an instance of a registered decompiler.

        Args:
            name: Name of the decompiler
            config: Optional configuration

        Returns:
            Decompiler instance

        Raises:
            KeyError: If decompiler is not registered
        """
        if name not in cls._decompilers:
            available = ", ".join(cls._decompilers.keys())
            raise KeyError(
                f"Decompiler '{name}' not found. Available: {available}"
            )

        return cls._decompilers[name](config)

    @classmethod
    def list_registered(cls) -> list[str]:
        """List all registered decompiler names."""
        return list(cls._decompilers.keys())

    @classmethod
    def list_available(cls) -> list[str]:
        """List decompilers that are available on the system."""
        available = []
        for name, dec_class in cls._decompilers.items():
            try:
                instance = dec_class()
                if instance.is_available():
                    available.append(name)
            except Exception:
                # Skip decompilers that fail to instantiate
                pass
        return available

    @classmethod
    def get_all(
        cls,
        names: list[str] | None = None,
        config: DecompilerConfig | None = None,
        only_available: bool = True,
    ) -> dict[str, Decompiler]:
        """Get multiple decompiler instances.

        Args:
            names: List of decompiler names, or None for all
            config: Optional configuration (applied to all)
            only_available: Only return available decompilers

        Returns:
            Dictionary mapping names to decompiler instances
        """
        if names is None:
            names = cls.list_registered()

        result = {}
        for name in names:
            try:
                dec = cls.get(name, config)
                if not only_available or dec.is_available():
                    result[name] = dec
            except (KeyError, Exception):
                pass

        return result

    @classmethod
    def clear(cls) -> None:
        """Clear all registered decompilers. Mainly for testing."""
        cls._decompilers.clear()


def register_decompiler(name: str) -> Callable[[type[T]], type[T]]:
    """Decorator to register a decompiler class.

    Usage:
        @register_decompiler("my_decompiler")
        class MyDecompiler(Decompiler):
            ...

    Args:
        name: Unique identifier for the decompiler

    Returns:
        Decorator function
    """
    def decorator(cls: type[T]) -> type[T]:
        DecompilerRegistry.register(name, cls)
        return cls

    return decorator
