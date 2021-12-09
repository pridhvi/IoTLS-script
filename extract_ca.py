from genericpath import exists
import pyshark
from pyshark.packet.fields import LayerField, LayerFieldsContainer
from pyshark.packet.layer import Layer
from pyshark.packet.packet import Packet
import re
from pathlib import Path
import os
import nest_asyncio
nest_asyncio.apply()

total_certs = 0
#device_count = {}

class TLSCert:
    def __init__(self):
        self.issuer = []
        self.subject = []

    def add_issuer_sequence(self, seq):
        self.issuer.append(seq)

    def add_subject_sequence(self, seq):
        self.subject.append(seq)

    def __str__(self):
        return "\tIssuer: " + str(self.issuer) + "\n\tSubject: " + str(self.subject)


def get_all(field_container):
    field_container: LayerFieldsContainer
    field_container = field_container.all_fields
    tmp = []
    field: LayerField
    for field in field_container:
        tmp.append(field.get_default_value())
    return tmp


def extract_certs(tls_layer):
    cert_count = 0
    if_rdnSequence_count = []
    af_rdnSequence_count = []
    rdn = []
    field_container: LayerFieldsContainer
    a = list(tls_layer._all_fields.values())
    for field_container in a:
        field: LayerField
        field = field_container.main_field

        if field.name == 'x509if.RelativeDistinguishedName_item_element':
            rdn = (get_all(field_container))
        elif field.name == 'x509af.signedCertificate_element':
            cert_count = len(field_container.all_fields)
        elif field.name == 'x509if.rdnSequence':
            if_rdnSequence_count = get_all(field_container)
        elif field.name == 'x509af.rdnSequence':
            af_rdnSequence_count = get_all(field_container)

    certs = []
    for i in range(cert_count):
        cert = TLSCert()
        for j in range(int(if_rdnSequence_count[i])):
            cert.add_issuer_sequence(rdn.pop(0))
        for j in range(int(af_rdnSequence_count[i])):
            cert.add_subject_sequence(rdn.pop(0))
        certs.append(cert)

    return certs

def analyzePacket(packet, ca_count):
    global total_certs
    packet: Packet
    layer: Layer
    layer = packet.tls
    cert_list = extract_certs(layer)

    for cert in cert_list:
        total_certs += 1
        result = re.search('id-at-commonName=[^\)]*', str(cert.issuer))
        if result is not None:
            ca_name = result.group(0)[17:]
            if ca_name in ca_count:
                ca_count[ca_name] = ca_count.get(ca_name) + 1
            else:
                ca_count[ca_name] = 1
            #print(ca_name)

    return ca_count

def main():
    directory = '/Users/pridhvi/Documents/uni/IoTLS/TLSHandshakesTraffic/'

    for devicemac in os.listdir(directory):
        devicefolder = os.path.join(directory, devicemac)

        if not os.path.isfile(devicefolder):
            # Getting the device name from MAC address(folder name)
            devices = open("/Users/pridhvi/Documents/uni/IoTLS/TLSHandshakesTraffic/devices.txt", "r")
            for line in devices:
                if devicemac in line:
                    devicename = line.split(' ')[1].rstrip()
                    print('\n##########')
                    print(devicename)
                    print('##########\n')
            devices.close()

            device_count = {}
            ca_count = {}
            files = Path(devicefolder).glob('*.pcap')
            for file in files:
                
                try:
                    capture = pyshark.FileCapture(str(file), display_filter='tls.handshake.certificate')
                    for packet in capture:
                        ca_count = analyzePacket(packet, ca_count)
                except Exception:
                    print("SKIP")

            device_count[devicename] = ca_count

            with open("output.txt", 'a') as f:
                for device in device_count:
                    f.write('----------\n')
                    f.write(device)
                    f.write('\n----------\n') 
                    for key in device_count[device]:  
                        f.write('%s -> %s\n' % (key, device_count[device][key]))

if __name__ == "__main__":
    main()
