"""
zigbee.py

By Greg Rapp, 2010
Inspired by code written by Paul Malmsten, 2010
Inspired by code written by Amit Synderman and Marco Sangalli
gdrapp@gmail.com

This module implements an XBee ZB (ZigBee) API library.
"""
import struct
from xbee.base import XBeeBase
from xbee.python2to3 import byteToInt

class ZigBee(XBeeBase):
    """
    Provides an implementation of the XBee API for XBee ZB (ZigBee) modules
    with recent firmware.

    Commands may be sent to a device by instantiating this class with
    a serial port object (see PySerial) and then calling the send
    method with the proper information specified by the API. Data may
    be read from a device synchronously by calling wait_read_frame.
    For asynchronous reads, see the defintion of XBeeBase.
    """
    # Packets which can be sent to an XBee

    # Format:
    #        {name of command:
    #           [{name:field name, len:field length, default: default value sent}
    #            ...
    #            ]
    #         ...
    #         }
    # pylint: disable = C0301
    api_commands = {"at":
                        [{'name':'id',        'len':1,      'default':b'\x08'},
                         {'name':'frame_id',  'len':1,      'default':b'\x01'},
                         {'name':'command',   'len':2,      'default':None},
                         {'name':'parameter', 'len':None,   'default':None}],
                    "queued_at":
                        [{'name':'id',        'len':1,      'default':b'\x09'},
                         {'name':'frame_id',  'len':1,      'default':b'\x01'},
                         {'name':'command',   'len':2,      'default':None},
                         {'name':'parameter', 'len':None,   'default':None}],
                    "remote_at":
                        [{'name':'id',              'len':1,        'default':b'\x17'},
                         {'name':'frame_id',        'len':1,        'default':b'\x00'},
                         # dest_addr_long is 8 bytes (64 bits), so use an unsigned long long
                         {'name':'dest_addr_long',  'len':8,        'default':struct.pack('>Q', 0)},
                         {'name':'dest_addr',       'len':2,        'default':b'\xFF\xFE'},
                         {'name':'options',         'len':1,        'default':b'\x02'},
                         {'name':'command',         'len':2,        'default':None},
                         {'name':'parameter',       'len':None,     'default':None}],
                    "tx":
                        [{'name':'id',              'len':1,        'default':b'\x10'},
                         {'name':'frame_id',        'len':1,        'default':b'\x01'},
                         {'name':'dest_addr_long',  'len':8,        'default':None},
                         {'name':'dest_addr',       'len':2,        'default':None},
                         {'name':'broadcast_radius','len':1,        'default':b'\x00'},
                         {'name':'options',         'len':1,        'default':b'\x00'},
                         {'name':'data',            'len':None,     'default':None}],
                    "tx_explicit":
                        [{'name':'id',              'len':1,        'default':b'\x11'},
                         {'name':'frame_id',        'len':1,        'default':b'\x00'},
                         {'name':'dest_addr_long',  'len':8,        'default':None},
                         {'name':'dest_addr',       'len':2,        'default':None},
                         {'name':'src_endpoint',    'len':1,        'default':None},
                         {'name':'dest_endpoint',   'len':1,        'default':None},
                         {'name':'cluster',         'len':2,        'default':None},
                         {'name':'profile',         'len':2,        'default':None},
                         {'name':'broadcast_radius','len':1,        'default':b'\x00'},
                         {'name':'options',         'len':1,        'default':b'\x00'},
                         {'name':'data',            'len':None,     'default':None}]
                    }
    # pylint: enable = C0301

    # Packets which can be received from an XBee

    # Format:
    #        {id byte received from XBee:
    #           {name: name of response
    #            structure:
    #                [ {'name': name of field, 'len':length of field}
    #                  ...
    #                  ]
    #            parse_as_io_samples:name of field to parse as io
    #           }
    #           ...
    #        }
    #
    api_responses = {
        b"\x90":
            {'name':'rx',
             'structure':
                [{'name':'source_addr_long','len':8},
                 {'name':'source_addr',     'len':2},
                 {'name':'options',         'len':1},
                 {'name':'rf_data',         'len':None}]},
         b"\x91":
            {'name':'rx_explicit',
             'structure':
                [{'name':'source_addr_long','len':8},
                 {'name':'source_addr',     'len':2},
                 {'name':'source_endpoint', 'len':1},
                 {'name':'dest_endpoint',   'len':1},
                 {'name':'cluster',         'len':2},
                 {'name':'profile',         'len':2},
                 {'name':'options',         'len':1},
                 {'name':'rf_data',         'len':None}]},
         b"\x92": # Checked by GDR-parse_samples_header function appears to need update to support
            {'name':'rx_io_data_long_addr',
             'structure':
                [{'name':'source_addr_long','len':8},
                 {'name':'source_addr',     'len':2},
                 {'name':'options',         'len':1},
                 {'name':'samples',         'len':None}],
             'parsing': [('samples',
                          lambda xbee,original: xbee._parse_samples(original['samples'])
                         )]},
         b"\x8b":
            {'name':'tx_status',
             'structure':
                [{'name':'frame_id',        'len':1},
                 {'name':'dest_addr',       'len':2},
                 {'name':'retries',         'len':1},
                 {'name':'deliver_status',  'len':1},
                 {'name':'discover_status', 'len':1}]},
         b"\x8a": {
             'name':'modem status',
             'structure': [
                 {'name':'status',      'len':1},
             ],
             'parsing': [
                 ('status', lambda self, original: self._parse_modem_status(original))
             ]
         },
         b"\x88":
            {'name':'at_response',
             'structure':
                [{'name':'frame_id',    'len':1},
                 {'name':'command',     'len':2},
                 {'name':'status',      'len':1},
                 {'name':'parameter',   'len':None}],
             'parsing': [
                 ('parameter', lambda self, original: self._parse_IS_at_response(original)),
                 ('parameter', lambda self, original: self._parse_ND_at_response(original)),
                 ('parameter', lambda self, original: self._parse_ai_at_response(original)),
                 ('parameter', lambda self, original: self._parse_sh_at_response(original)),
                 ('parameter', lambda self, original: self._parse_sl_at_response(original)),
                 ('parameter', lambda self, original: self._parse_my_at_response(original)),
                 ('parameter', lambda self, original: self._parse_ni_at_response(original)),
                 ('parameter', lambda self, original: self._parse_percentv_at_response(original)),
                 ('parameter', lambda self, original: self._parse_tp_at_response(original)),
                 ('parameter', lambda self, original: self._parse_vr_at_response(original)),
                 ('parameter', lambda self, original: self._parse_hv_at_response(original)),
                 ('parameter', lambda self, original: self._parse_id_at_response(original)),
                 ('parameter', lambda self, original: self._parse_op_at_response(original)),
                 ('parameter', lambda self, original: self._parse_oi_at_response(original)),
                 ('parameter', lambda self, original: self._parse_pl_at_response(original)),
                 ('parameter', lambda self, original: self._parse_db_at_response(original)),
                 ('parameter', lambda self, original: self._parse_pp_at_response(original)),
                 ('status', lambda self, original: self._parse_at_response_status(original)),
             ]
                 },
         b"\x97": #Checked GDR (not sure about parameter, could be 4 bytes)
            {'name':'remote_at_response',
             'structure':
                [{'name':'frame_id',        'len':1},
                 {'name':'source_addr_long','len':8},
                 {'name':'source_addr',     'len':2},
                 {'name':'command',         'len':2},
                 {'name':'status',          'len':1},
                 {'name':'parameter',       'len':None}],
              'parsing': [
                    ('parameter', lambda self, original: self._parse_IS_at_response(original)),
                    ('parameter', lambda self, original: self._parse_ai_at_response(original)),
                    ('parameter', lambda self, original: self._parse_sh_at_response(original)),
                    ('parameter', lambda self, original: self._parse_sl_at_response(original)),
                    ('parameter', lambda self, original: self._parse_my_at_response(original)),
                    ('parameter', lambda self, original: self._parse_ni_at_response(original)),
                    ('parameter', lambda self, original: self._parse_percentv_at_response(original)),
                    ('parameter', lambda self, original: self._parse_tp_at_response(original)),
                    ('parameter', lambda self, original: self._parse_vr_at_response(original)),
                    ('parameter', lambda self, original: self._parse_hv_at_response(original)),
                    ('parameter', lambda self, original: self._parse_id_at_response(original)),
                    ('parameter', lambda self, original: self._parse_op_at_response(original)),
                    ('parameter', lambda self, original: self._parse_oi_at_response(original)),
                    ('parameter', lambda self, original: self._parse_pl_at_response(original)),
                    ('parameter', lambda self, original: self._parse_db_at_response(original)),
                    ('parameter', lambda self, original: self._parse_pp_at_response(original)),
                    ('status', lambda self, original: self._parse_at_response_status(original)),
              ]
                 },
         b"\x95":
            {'name':'node_id_indicator',
             'structure':
                [{'name':'sender_addr_long','len':8},
                 {'name':'sender_addr',     'len':2},
                 {'name':'options',         'len':1},
                 {'name':'source_addr',     'len':2},
                 {'name':'source_addr_long','len':8},
                 {'name':'node_id',         'len':'null_terminated'},
                 {'name':'parent_source_addr','len':2},
                 {'name':'device_type',     'len':1},
                 {'name':'source_event',    'len':1},
                 {'name':'digi_profile_id', 'len':2},
                 {'name':'manufacturer_id', 'len':2}]}
         }

    def _parse_IS_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an IS
        command, parse the parameter field as IO data.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'is' \
            and packet['status'] == b'\x00':
            return self._parse_samples(packet['parameter'])
        else:
            return packet['parameter']

    def _parse_ND_at_response(self, packet):
        """
        If the given packet is a successful AT response for an ND
        command, parse the parameter field.
        """
        if packet['id'] == 'at_response' \
            and packet['command'].lower() == b'nd' \
            and packet['status'] == b'\x00':
            result = {}

            # Parse each field directly
            result['source_addr'] = packet['parameter'][0:2]
            result['source_addr_long'] = packet['parameter'][2:10]

            # Parse the null-terminated node identifier field
            null_terminator_index = 10
            while packet['parameter'][null_terminator_index:null_terminator_index+1] != b'\x00':
                null_terminator_index += 1;

            # Parse each field thereafter directly
            result['node_identifier'] = packet['parameter'][10:null_terminator_index]
            result['parent_address'] = packet['parameter'][null_terminator_index+1:null_terminator_index+3]
            result['device_type'] = packet['parameter'][null_terminator_index+3:null_terminator_index+4]
            result['status'] = packet['parameter'][null_terminator_index+4:null_terminator_index+5]
            result['profile_id'] = packet['parameter'][null_terminator_index+5:null_terminator_index+7]
            result['manufacturer'] = packet['parameter'][null_terminator_index+7:null_terminator_index+9]

            # Simple check to ensure a good parse
            if null_terminator_index+9 != len(packet['parameter']):
               raise ValueError("Improper ND response length: expected {0}, read {1} bytes".format(len(packet['parameter']), null_terminator_index+9))

            return result
        else:
            return packet['parameter']

    def __init__(self, *args, **kwargs):
        # Call the super class constructor to save the serial port
        super(ZigBee, self).__init__(*args, **kwargs)

    def _parse_samples_header(self, io_bytes):
        """
        _parse_samples_header: binary data in XBee ZB IO data format ->
                        (int, [int ...], [int ...], int, int)

        _parse_samples_header will read the first three bytes of the
        binary data given and will return the number of samples which
        follow, a list of enabled digital inputs, a list of enabled
        analog inputs, the dio_mask, and the size of the header in bytes

        _parse_samples_header is overloaded here to support the additional
        IO lines offered by the XBee ZB
        """
        header_size = 4

        # number of samples (always 1?) is the first byte
        sample_count = byteToInt(io_bytes[0])

        # bytes 1 and 2 are the DIO mask; bits 9 and 8 aren't used
        dio_mask = (byteToInt(io_bytes[1]) << 8 | byteToInt(io_bytes[2])) \
                & 0x0E7F

        # byte 3 is the AIO mask
        aio_mask = byteToInt(io_bytes[3])

        # sorted lists of enabled channels; value is position of bit in mask
        dio_chans = []
        aio_chans = []

        for i in range(0, 13):
            if dio_mask & (1 << i):
                dio_chans.append(i)

        dio_chans.sort()

        for i in range(0, 8):
            if aio_mask & (1 << i):
                aio_chans.append(i)

        aio_chans.sort()

        return (sample_count, dio_chans, aio_chans, dio_mask, header_size)

    def _parse_modem_status(self, packet):
        """
        Parse the status field of the given modem status message.
        """
        status = {
            '\x00' : 'Hardware reset',
            '\x01' : 'Watchdog timer reset',
            '\x02' : 'Joined network',
            '\x03' : 'Disassociated',
            '\x06' : 'Coordinator started',
            '\x07' : 'Network security was updated',
            '\x0d' : 'Voltage supply limit exceeded',
            '\x11' : 'Modem configuration changed while join in progress',
        }

        if packet['status'] in status:
            return status[packet['status']]
        else:
            return packet['status']

    def _parse_ai_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an AI
        command, convert the parameter field to meaningful string.
        """
        assoc_indic = {
            '\x00' : '0x00 - Successfully formed or joined a network',
            '\x21' : '0x21 - Scan found no PANs',
            '\x22' : '0x22 - Scan found no valid PANs based on current SC and ID settings',
            '\x23' : '0x23 - Valid Coordinator or Routers found, but they are not allowing joining (NJ expired)',
            '\x24' : '0x24 - No joinable beacons were found',
            '\x25' : '0x25 - Unexpected state, node should not be attempting to join at this time',
            '\x27' : '0x27 - Node Joining attempt failed (typically due to incompatible security settings)',
            '\x2a' : '0x2a - Coordinator Start attempt failed',
            '\x2b' : '0x2b - Checking for an existing coordinator',
            '\x2c' : '0x2c - Attempt to leave the network failed',
            '\xab' : '0xab - Attempted to join a device that did not respond',
            '\xac' : '0xac - Secure join error - network security key received unsecured',
            '\xad' : '0xad - Secure join error - network security key not received',
            '\xaf' : '0xaf - Secure join error - joining device does not have the right preconfigured link key',
            '\xff' : '0xff - Scanning for a ZigBee network',
		}

        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'ai' \
            and packet['status'] == b'\x00' \
            and packet['parameter'] in assoc_indic:
            return assoc_indic[packet['parameter']]
        else:
            return packet['parameter']

    def _parse_at_response_status(self, packet):
        """
        If the given packet is a successful remote AT response for an CE
        command, convert the parameter field to meaningful string.
        """
        ce_status = {
            '\x00' : '0x00 - OK',
            '\x01' : '0x01 - ERROR',
            '\x02' : '0x02 - Invalid Command',
            '\x03' : '0x03 - Invalid Parameter',
            '\x04' : '0x04 - Tx Failure',
		}

        if packet['id'] in ('at_response','remote_at_response') \
            and packet['status'] in ce_status:
            return ce_status[packet['status']]
        else:
            return packet['status']

    def _parse_sh_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an SH command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'sh' \
            and packet['status'] == b'\x00':
            return 'serial high: ' \
                    + ''.join(['%02x' % ord(p) for p in packet['parameter']])
        else:
            return packet['parameter']

    def _parse_sl_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an SL command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'sl' \
            and packet['status'] == b'\x00':
            return 'serial low : ' \
                    + ''.join(['%02x' % ord(p) for p in packet['parameter']])
        else:
            return packet['parameter']

    def _parse_my_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an MY command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'my' \
            and packet['status'] == b'\x00':
            return 'network @: ' \
                    + ''.join(['%02x' % ord(p) for p in packet['parameter']])
        else:
            return packet['parameter']

    def _parse_ni_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an NI command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'ni' \
            and packet['status'] == b'\x00':
            return 'node id: [%s]' % packet['parameter']
        else:
            return packet['parameter']

    def _parse_percentv_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an %V command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'%v' \
            and packet['status'] == b'\x00':
            voltage = (ord(packet['parameter'][0]) << 8) \
                + ord(packet['parameter'][1])
            return 'voltage: %d mV' % voltage
        else:
            return packet['parameter']

    def _parse_tp_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an TP command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'tp' \
            and packet['status'] == b'\x00':
            temp = (ord(packet['parameter'][0]) << 8) \
                + ord(packet  ['parameter'][1])
            return 'temperature: %d C' % temp
        else:
            return packet['parameter']

    def _parse_vr_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an VR command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'vr' \
            and packet['status'] == b'\x00':
            return 'firmware: 0x' \
                    + ''.join(['%02x' % ord(p) for p in packet['parameter']])
        else:
            return packet['parameter']

    def _parse_hv_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an HV command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'hv' \
            and packet['status'] == b'\x00':
            return 'hardware: ' \
                    + ''.join(['%02x' % ord(p) for p in packet['parameter']])
        else:
            return packet['parameter']

    def _parse_id_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an ID command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'id' \
            and packet['status'] == b'\x00':
            return 'extended PAN ID: ' \
                    + ''.join(['%02x' % ord(p) for p in packet['parameter']])
        else:
            return packet['parameter']

    def _parse_op_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an OP command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'op' \
            and packet['status'] == b'\x00':
            return 'operating extended PAN ID: ' \
                    + ''.join(['%02x' % ord(p) for p in packet['parameter']])
        else:
            return packet['parameter']

    def _parse_oi_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an OI command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'oi' \
            and packet['status'] == b'\x00':
            return 'operating 16-bit PAN ID: ' \
                    + ''.join(['%02x' % ord(p) for p in packet['parameter']])
        else:
            return packet['parameter']

    def _parse_pl_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an PL command,
		parse the parameter field.
        """
        power_level = {
			4 : '+18 dBm',
			3 : '+16 dBm',
			2 : '+14 dBm',
			1 : '+12 dBm',
			0 : '+0 dBm',
		}

        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'pl' \
            and packet['status'] == b'\x00' \
            and ord(packet['parameter']) in power_level:
            return 'power level: %s' % power_level[ord(packet['parameter'])]
        else:
            return packet['parameter']

    def _parse_db_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an DB command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'db' \
            and packet['status'] == b'\x00':
            return 'received signal strength: -%d dBm' \
                    % ord(packet['parameter'])
        else:
            return packet['parameter']

    def _parse_pp_at_response(self, packet):
        """
        If the given packet is a successful remote AT response for an PP command,
		parse the parameter field.
        """
        if packet['id'] in ('at_response','remote_at_response') \
            and packet['command'].lower() == b'pp' \
            and packet['status'] == b'\x00':
            return 'peak power: %d dBm' % ord(packet['parameter'])
        else:
            return packet['parameter']

