#!/usr/bin/env python3
# coding: utf8

import abc
from typing import Any
from scat.iodevices.abstractio import AbstractIO
from scat.writers.abstractwriter import AbstractWriter

class AbstractParser(metaclass=abc.ABCMeta):
    name: str
    shortname: str

    @abc.abstractmethod
    def set_io_device(self, io_device: AbstractIO) -> None:
        return

    @abc.abstractmethod
    def set_writer(self, writer: AbstractWriter) -> None:
        return

    @abc.abstractmethod
    def set_parameter(self, params: dict[str, Any]) -> None:
        return

    @abc.abstractmethod
    def init_diag(self) -> None:
        return

    @abc.abstractmethod
    def prepare_diag(self) -> None:
        return

    @abc.abstractmethod
    def stop_diag(self) -> None:
        return

    @abc.abstractmethod
    def run_diag(self, writer: AbstractWriter | None = None) -> None:
        return

    @abc.abstractmethod
    def read_dump(self) -> None:
        return