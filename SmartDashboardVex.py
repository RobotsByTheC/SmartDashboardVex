#!/usr/bin/env python3

import binascii
from enum import IntEnum
import numbers
import sys

from networktables import NetworkTable
import serial.tools.list_ports

MAX_PACKET_LENGTH = 100

CHAR_BEG = 0x02
CHAR_SEP = 0x03
CHAR_ESC = 0x04
CHAR_END = 0x05

receiveList = {}

class DataType(IntEnum):
    INT = 0x06
    BOOL = 0x07

def info(msg):
    print(msg, flush=True)

def debug(msg):
    if debug_enabled:
        info(msg)

def hex_dump(data):
    return str(binascii.hexlify(bytes(data)), sys.getdefaultencoding())

def parse_args():
    import argparse
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--debug", help="print debug messages", action="store_true")
    parser.add_argument("--dev", help="serial device used to communicate with the Vex", default=None)
    
    args = parser.parse_args()
    
    global debug_enabled
    global serial_device
    debug_enabled = args.debug
    serial_device = args.dev

def open_serial(device=None):
    if device == None:
        ports = serial.tools.list_ports.grep("2303")
        try:
            device = next(ports)[0]
        except:
            device = 0

    debug("open_serial(): Using serial port: %s" % device)
    serial_conn = serial.Serial(device, baudrate=115200)
    # Loop device for testing

    serial_conn.flushInput()
    return serial_conn

def escape_data(packet):
    i = 0
    while i < len(packet):
        char = packet[i]
        if (char == CHAR_BEG or
         char == CHAR_END or 
         char == CHAR_SEP or 
         char == CHAR_ESC):
            packet.insert(i, CHAR_ESC)
            i += 1
        i += 1

def send_int(serial_conn, name, value):
    send_packet(serial_conn, name, DataType.INT, value.to_bytes(4, byteorder='little', signed=True))

def send_bool(serial_conn, name, value):
    send_packet(serial_conn, name, DataType.BOOL, 1 if value else 0)
    
def send_packet(serial_conn, name, data_type, value_bytes):
    name = bytearray(name, "UTF-8")
    value_bytes = bytearray(value_bytes)
    escape_data(name)
    escape_data(value_bytes)
    
    packet = bytes((CHAR_BEG,)) + name + bytes((CHAR_SEP,)) + bytes((data_type,)) + value_bytes + bytes((CHAR_END,))
    debug("send_packet(): packet=%s" % hex_dump(packet));
    
    if len(packet) <= MAX_PACKET_LENGTH:
        serial_conn.write(packet)
    else:
        raise IOError("Packet length (%i) greater than %i." % (len(packet), MAX_PACKET_LENGTH))

def recieve_packets(serial_conn):
    name = bytearray()
    value = bytearray()
    value_section = False
    
    def append_byte(val):
        if value_section:
            value.append(val)
        else:
            name.append(val)
    
    esc = False
    began = False
    
    def process_data(name, value):
        debug("process_data(): name=%s, value=%s" % (hex_dump(name), hex_dump(value)))
        try:
            name = str(name, "UTF-8")
            value_len = len(value)
            if value_len > 1:
                value_type = DataType(value[0])
                if value_type == DataType.INT:
                    if value_len == 5:
                            return (name, int.from_bytes(value[1:], byteorder='big', signed=True))
                elif value_type == DataType.BOOL:
                    if value_len == 2:
                        return (name, value[1] > 0)
        except (ValueError, UnicodeDecodeError) as e:
            debug("process_data(): %s" % e)
                
    while True:
        data = serial_conn.read()
        if len(data) == 1:
            data_val = data[0]
            if not esc:
                if data_val == CHAR_ESC:
                    esc = True
                elif data_val == CHAR_BEG:
                    began = True
                    name.clear()
                    value.clear()
                    value_section = False
                elif data_val == CHAR_SEP:
                    if began:
                        value_section = True
                elif data_val == CHAR_END:
                    if began:
                        result = process_data(name, value)
                        if result:
                            debug("recieve_packets(): name=%s, value=%s" % (result[0], result[1]))
                            yield result
                else:
                    if began:
                        append_byte(data_val)
            else:
                if began:
                    esc = False
                    append_byte(data_val)
        else:
            raise IOError("Timeout while reading from Vex controller")

def run_server(serial_conn):
    sd = NetworkTable.getTable("SmartDashboard")
    
    def value_changed(table, key, value, is_new):
        debug("value_changed(): key='%s', value=%s, is_new=%s" % (key, value, is_new))
        if key in receiveList and receiveList[key] == value:
            debug("value_changed(): update was caused by receive")
            del receiveList[key]
        else:
            if isinstance(value, numbers.Number):
                try:
                    send_int(serial_conn, key, round(value))
                except OverflowError:
                    info("Integer too big to be sent: key=%s, value=%s" % (key, value));
            elif isinstance(value, bool):
                send_bool(serial_conn, key, value)

    sd.addTableListener(value_changed)
    
    for name, value in recieve_packets(serial_conn):
        receiveList[name] = value
        if isinstance(value, numbers.Number):
            sd.putNumber(name, value)
        elif isinstance(value, bool):
            sd.putBoolean(name, value)

if __name__ == "__main__":
    
    parse_args()
    
    try:
        run_server(open_serial(serial_device))
#         run_server(None)
    except Exception as e:
        # Throw the exception if debug is enabled, otherwise just print it and exit
        if debug_enabled:
            raise e
        else:
            print("Error: %s" % e, flush=True, file=sys.stderr)
            exit(1)
    except:
        exit(2)
    
