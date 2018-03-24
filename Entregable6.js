load("Utils.js");
card = new Card();
atr = card.reset(Card.RESET_COLD);
//print(atr);
print("");
print("PRESENTACION del IC para iniciar: ACOSTEST= 41434F53 54455354");
resp = card.plainApdu(new ByteString("80 20 07 00 08 41 43 4F 53 54 45 53 54", HEX));
print("Código SW: " + card.SW.toString(16));

print("          FICHERO ACCOUNT SECURETY FILE FF06 8 RECORDS DE OCHO BYTES");
resp = card.plainApdu(new ByteString(SelectHex("FF 06"),HEX));
print("");

print("Registro 0");
resp = card.plainApdu(new ByteString(WriteHex("00","00","08","80 81 82 83 84 85 86 87"),HEX));
print("Código SW: " + card.SW.toString(16));

print("Registro 1");
resp = card.plainApdu(new ByteString(WriteHex("01","00","08","90 91 92 93 94 95 96 97"),HEX));
print("Código SW: " + card.SW.toString(16));

print("Registro 2");
resp = card.plainApdu(new ByteString(WriteHex("02","00","08","A0 A1 A2 A3 A4 A5 A6 A7"),HEX));
print("Código SW: " + card.SW.toString(16));

print("Registro 3");
resp = card.plainApdu(new ByteString(WriteHex("03","00","08","B0 B1 B2 B3 B4 B5 B6 B7"),HEX));
print("Código SW: " + card.SW.toString(16));

print("Registro 4");
resp = card.plainApdu(new ByteString(WriteHex("04","00","08","88 89 8A 8B 8C 8D 8E 8F"),HEX));
print("Código SW: " + card.SW.toString(16));

print("Registro 5");
resp = card.plainApdu(new ByteString(WriteHex("05","00","08","98 99 9A 9B 9C 9D 9E 9F"),HEX));
print("Código SW: " + card.SW.toString(16));

print("Registro 6");
resp = card.plainApdu(new ByteString(WriteHex("06","00","08","A8 A9 AA AB AC AD AE AF"),HEX));
print("Código SW: " + card.SW.toString(16));

print("Registro 7");
resp = card.plainApdu(new ByteString(WriteHex("07","00","08","B8 B9 BA BB BC BD BE BF"),HEX));
print("Código SW: " + card.SW.toString(16));