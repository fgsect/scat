#!/usr/bin/env python3
# coding: utf8

import abc

class AbstractIO(metaclass=abc.ABCMeta):
    block_until_data: bool
    file_available: bool
    fname: str

    @abc.abstractmethod
    def open_next_file(self) -> None:
        return

    @abc.abstractmethod
    def read(self, read_size: int, decode_hdlc: bool = False) -> bytes:
        return b''

    @abc.abstractmethod
    def write(self, write_buf: bytes, encode_hdlc: bool = False) -> None:
        return

    @abc.abstractmethod
    def write_then_read_discard(self, write_buf: bytes, read_size: int, encode_hdlc: bool = False) -> None:
        return