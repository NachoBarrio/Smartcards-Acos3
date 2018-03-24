/* LEE LOS FICHEROS DE LA ZONA DE MEMORIA INTERNA DE LA ACOS3 */


card = new Card();
atr = card.reset(Card.RESET_COLD);
//print(atr);
print("");
print("PRESENTACION del IC para iniciar: ACOSTEST= 41434F53 54455354");
resp = card.plainApdu(new ByteString("80 20 07 00 08 41 43 4F 53 54 45 53 54", HEX));
print("Código SW: " + card.SW.toString(16));
print("");

//print("SE SELECCIONA EL FICHERO MCU-ID FILE FILE FF00");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 FF 00", HEX));
print("          MCU-ID FILE FILE FF00");
resp = card.plainApdu(new ByteString("80 B2 00 00 08", HEX));
print("");
print("MCU-ID FILE Record Nº 0:" + "  " + resp + "   " + resp.toString(ASCII));
resp = card.plainApdu(new ByteString("80 B2 01 00 08", HEX));
print("MCU-ID FILE Record Nº 1:" + "  " + resp + "   " + resp.toString(ASCII));
print("");

print("          MANUFACTURER FILE FF01");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 FF 01", HEX));
print("");
print("MANUFACTURER FILE FF01 TIENE 2 RECORDS DE 8 BYTES.");
resp = card.plainApdu(new ByteString("80 B2 00 00 08", HEX));
print("");
print("MANUFACTURER FILE Record Nº 00:" + "  " + resp);
resp = card.plainApdu(new ByteString("80 B2 01 00 08", HEX));
print("MANUFACTURER FILE Record Nº 01:" + "  " + resp);
print("");

//print("          PERSONALIZATION FILE FF02");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 FF 02", HEX));

print("PERSONALIZATION FILE FF02 TIENE 3 RECORDS DE 4 BYTES.");
resp = card.plainApdu(new ByteString("80 B2 00 00 04", HEX));
print("");
print("PERSONALIZATION FILE Record Nº 00:" + "  " + resp);
resp = card.plainApdu(new ByteString("80 B2 01 00 04", HEX));
print("PERSONALIZATION FILE Record Nº 01:" + "  " + resp);
resp = card.plainApdu(new ByteString("80 B2 02 00 04", HEX));
print("PERSONALIZATION FILE Record Nº 02:" + "  " + resp);
print("");


print("          FICHERO SECURITY FILE FF03 TIENE 14 RECORDS DE 8 BYTES");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 FF 03", HEX));
print("");

resp = card.plainApdu(new ByteString("80 B2 00 00 08", HEX));
print("SECURITY FILE Record Nº 00:" + "  " + resp + "   " + resp.toString(ASCII));

resp = card.plainApdu(new ByteString("80 B2 01 00 08", HEX));
print("SECURITY FILE Record Nº 01:" + "  " + resp + "   " + resp.toString(ASCII));

resp = card.plainApdu(new ByteString("80 B2 02 00 08", HEX));
print("SECURITY FILE Record Nº 02:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 03 00 08", HEX));
print("SECURITY FILE Record Nº 03:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 04 00 08", HEX));
print("SECURITY FILE Record Nº 04:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 05 00 08", HEX));
print("SECURITY FILE Record Nº 05:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 06 00 08", HEX));
print("SECURITY FILE Record Nº 06:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 07 00 08", HEX));
print("SECURITY FILE Record Nº 07:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 08 00 08", HEX));
print("SECURITY FILE Record Nº 08:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 09 00 08", HEX));
print("SECURITY FILE Record Nº 09:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 0A 00 08", HEX));
print("SECURITY FILE Record Nº 0A:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 0B 00 08", HEX));
print("SECURITY FILE Record Nº 0B:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 0C 00 08", HEX));
print("SECURITY FILE Record Nº 0C:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 0D 00 08", HEX));
print("SECURITY FILE Record Nº 0D:" + "  " + resp);
print("");

print("          FICHERO USER FILE MANAGEMENT FF04");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 FF 04", HEX));
print("");

resp = card.plainApdu(new ByteString("80 B2 00 00 07", HEX));
print("USER FILE MANAGEMENT Record Nº 00:" + "  " + resp);
resp = card.plainApdu(new ByteString("80 B2 01 00 07", HEX));
print("USER FILE MANAGEMENT Record Nº 01:" + "  " + resp);
resp = card.plainApdu(new ByteString("80 B2 02 00 07", HEX));
print("USER FILE MANAGEMENT Record Nº 02:" + "  " + resp);
resp = card.plainApdu(new ByteString("80 B2 03 00 07", HEX));
print("USER FILE MANAGEMENT Record Nº 03:" + "  " + resp);
resp = card.plainApdu(new ByteString("80 B2 04 00 07", HEX));
print("USER FILE MANAGEMENT Record Nº 04:" + "  " + resp);
resp = card.plainApdu(new ByteString("80 B2 05 00 07", HEX));
print("USER FILE MANAGEMENT Record Nº 05:" + "  " + resp);
resp = card.plainApdu(new ByteString("80 B2 06 00 07", HEX));
print("USER FILE MANAGEMENT Record Nº 06:" + "  " + resp);
resp = card.plainApdu(new ByteString("80 B2 07 00 07", HEX));
print("USER FILE MANAGEMENT Record Nº 07:" + "  " + resp);

print("Código SW:" + card.SW.toString(16));
print("");


print("          FICHERO ACCOUNT FILE FF05 OCHO RECORDS DE CUATRO BYTES");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 FF 05", HEX));
print("");

resp = card.plainApdu(new ByteString("80 B2 00 00 04", HEX));
print("ACCOUNT FILE Record Nº 00:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 01 00 04", HEX));
print("ACCOUNT FILE Record Nº 01:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 02 00 04", HEX));
print("ACCOUNT FILE Record Nº 02:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 03 00 04", HEX));
print("ACCOUNT FILE Record Nº 03:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 04 00 04", HEX));
print("ACCOUNT FILE Record Nº 04:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 05 00 04", HEX));
print("ACCOUNT FILE Record Nº 05:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 06 00 04", HEX));
print("ACCOUNT FILE Record Nº 06:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 07 00 04", HEX));
print("ACCOUNT FILE Record Nº 07:" + "  " + resp);
print("");

print("          FICHERO ACCOUNT SECURETY FILE FF06 8 RECORDS DE OCHO BYTES");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 FF 06", HEX));
print("");

resp = card.plainApdu(new ByteString("80 B2 00 00 08", HEX));
print("ACCOUNT FILE Record Nº 00:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 01 00 08", HEX));
print("ACCOUNT FILE Record Nº 01:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 02 00 08", HEX));
print("ACCOUNT FILE Record Nº 02:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 03 00 08", HEX));
print("ACCOUNT FILE Record Nº 03:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 04 00 08", HEX));
print("ACCOUNT FILE Record Nº 04:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 05 00 08", HEX));
print("ACCOUNT FILE Record Nº 05:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 06 00 08", HEX));
print("ACCOUNT FILE Record Nº 06:" + "  " + resp);

resp = card.plainApdu(new ByteString("80 B2 07 00 08", HEX));
print("ACCOUNT FILE Record Nº 07:" + "  " + resp);

print();
print("          FICHERO ATR FILE FF07 UN RECORDS DE 36 BYTES");
resp = card.plainApdu(new ByteString("80 A4 00 00 02 FF 07", HEX));
print("");

resp = card.plainApdu(new ByteString("80 B2 00 00 24", HEX));
print("ATR FILE Record Nº 00:" + "  " + resp);

print("");
print("Código SW: " + card.SW.toString(16));











