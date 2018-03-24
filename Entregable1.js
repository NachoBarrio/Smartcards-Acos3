load("Utils.js");
card = new Card();
atr = card.reset(Card.RESET_COLD);
//print(atr);
print("");
print("PRESENTACION del IC para iniciar: ACOSTEST= 41434F53 54455354");
resp = card.plainApdu(new ByteString("80 20 07 00 08 41 43 4F 53 54 45 53 54", HEX));
print("Código SW: " + card.SW.toString(16));
print("");

//print("          PERSONALIZATION FILE FF02");
//resp = card.plainApdu(new ByteString("80 A4 00 00 02 FF 02", HEX));
resp = card.plainApdu(new ByteString(SelectHex("FF 02"),HEX));
print("Código SW: " + card.SW.toString(16));
print("");
//resp = card.plainApdu(new ByteString("80 D2 00 00 03 25 54 04",HEX));
resp = card.plainApdu(new ByteString(WriteHex("00","00","03","25 54 04"),HEX));
print("Código SW: " + card.SW.toString(16));
print("");