load("Utils.js");
card = new Card();
atr = card.reset(Card.RESET_COLD);
//print(atr);
print("");
print("PRESENTACION del IC para iniciar: ACOSTEST= 41434F53 54455354");
resp = card.plainApdu(new ByteString("80 20 07 00 08 41 43 4F 53 54 45 53 54", HEX));
print("Código SW: " + card.SW.toString(16));

print("          FICHERO ACCOUNT FILE FF05 OCHO RECORDS DE CUATRO BYTES");
resp = card.plainApdu(new ByteString(SelectHex("FF 05"),HEX));
print("");

print("Transtyp 0");
resp = card.plainApdu(new ByteString(WriteHex("00","00","01","01"),HEX));
print("Código SW: " + card.SW.toString(16));

print("Transtyp 1");
resp = card.plainApdu(new ByteString(WriteHex("02","00","01","01"),HEX));
print("Código SW: " + card.SW.toString(16));

print("Balance 0");
resp = card.plainApdu(new ByteString(WriteHex("00","01","03","00 15 7C"),HEX));
//resp = card.plainApdu(new ByteString(WriteHex("00","01","03","00 00 00"),HEX));
print("Código SW: " + card.SW.toString(16));

print("Balance 1");
resp = card.plainApdu(new ByteString(WriteHex("02","01","03","00 15 7C"),HEX));
//resp = card.plainApdu(new ByteString(WriteHex("02","01","03","00 00 00"),HEX));
print("Código SW: " + card.SW.toString(16));

print("ATC 0");
resp = card.plainApdu(new ByteString(WriteHex("01","00","02","00 00"),HEX));
print("Código SW: " + card.SW.toString(16));

print("ATC 1");
resp = card.plainApdu(new ByteString(WriteHex("03","00","02","00 00"),HEX));
print("Código SW: " + card.SW.toString(16));

var sumaValores = ByteString.valueOf(0x15 + 0x7C + 0x01 +0x01);
sumaValores = sumaValores.bytes(sumaValores.length-1,1);

print("CHKSUM 0");
resp = card.plainApdu(new ByteString(WriteHex("01","02","01",sumaValores),HEX));
print("Código SW: " + card.SW.toString(16));

print("CHKSUM 1");
resp = card.plainApdu(new ByteString(WriteHex("03","02","01",sumaValores),HEX));
print("Código SW: " + card.SW.toString(16));

print("Balance Maximo");
resp = card.plainApdu(new ByteString(WriteHex("04","00","03","00 27 10"),HEX));
print("Código SW: " + card.SW.toString(16));

print("AID");
resp = card.plainApdu(new ByteString(WriteHex("05","00","04","CC CC 00 01"),HEX));
print("Código SW: " + card.SW.toString(16));

print("TTREF-C");
resp = card.plainApdu(new ByteString(WriteHex("06","00","04","AA DD CC 01"),HEX));
print("Código SW: " + card.SW.toString(16));

print("TTREF-D");
resp = card.plainApdu(new ByteString(WriteHex("07","00","04","EE CC 00 01"),HEX));
print("Código SW: " + card.SW.toString(16));
