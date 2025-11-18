#!/usr/bin/env python3
# coding: utf8

import abc
import datetime

class AbstractWriter(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def write_cp(self, sock_content: bytes, radio_id: int=0, ts: datetime.datetime | None = None) -> None:
        return

    @abc.abstractmethod
    def write_up(self, sock_content: bytes, radio_id: int=0, ts: datetime.datetime | None = None) -> None:
        return
