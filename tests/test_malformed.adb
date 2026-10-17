--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Malformed-input tests: truncation, trailer mismatch, bad SHB magic,
--  and unknown-block skip must all behave without raising.

with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Blocks;
with Pcapng_In_Ada.SHB;
with Pcapng_In_Ada.Reader;
with Pcapng_In_Ada.Writer;

procedure Test_Malformed is
   Fail : Natural := 0;

   procedure Check (Name : String; Ok : Boolean) is
   begin
      if Ok then
         Put_Line ("ok   " & Name);
      else
         Put_Line ("FAIL " & Name);
         Fail := Fail + 1;
      end if;
   end Check;

begin
   --  1. Truncated SHB.
   declare
      Buf : Byte_Buffer (1 .. 10) := [others => 0];
      V   : SHB.SHB_View;
      Nx  : Natural;
      Er  : Error_Kind;
   begin
      SHB.Parse_SHB (Buf, Buf'First, V, Nx, Er);
      Check ("truncated shb -> Truncated", Er = Truncated);
   end;

   --  2. Trailer mismatch.
   declare
      Buf   : Byte_Buffer (1 .. 64) := [others => 0];
      Last  : Natural := Buf'First - 1;
      Error : Error_Kind;
   begin
      Writer.Append_SHB (Buf, Last, Error);
      Buf (Last - 1) := 16#FF#;  --  corrupt trailing length
      declare
         Hdr : Blocks.Block_Header;
         Nx  : Natural;
         Er  : Error_Kind;
      begin
         Blocks.Parse_Header (Buf, Buf'First, Little_Endian, Hdr, Nx, Er);
         Check ("trailer mismatch -> Bad_Trailer", Er = Bad_Trailer);
      end;
   end;

   --  3. Bad SHB magic.
   declare
      Buf : Byte_Buffer (1 .. 28) := [others => 16#AA#];
      V   : SHB.SHB_View;
      Nx  : Natural;
      Er  : Error_Kind;
   begin
      SHB.Parse_SHB (Buf, Buf'First, V, Nx, Er);
      Check ("bad magic rejected",
             Er = Bad_Magic or else Er = Bad_Length or else Er = Truncated);
   end;

   --  4. Unknown block is skipped, walk continues.
   declare
      Buf   : Byte_Buffer (1 .. 256) := [others => 0];
      Last  : Natural := Buf'First - 1;
      Error : Error_Kind;
      Cur   : Reader.Cursor;
      Curr  : Reader.Current_Block;
      Seen_Unknown : Boolean := False;
      Count : Natural := 0;
   begin
      Writer.Append_SHB (Buf, Last, Error);
      --  Hand-roll an unknown block type 16#1234_5678#, len 12.
      Buf (Last + 1) := 16#78#;
      Buf (Last + 2) := 16#56#;
      Buf (Last + 3) := 16#34#;
      Buf (Last + 4) := 16#12#;
      Buf (Last + 5) := 12;
      Buf (Last + 6) := 0;
      Buf (Last + 7) := 0;
      Buf (Last + 8) := 0;
      Buf (Last + 9) := 12;
      Buf (Last + 10) := 0;
      Buf (Last + 11) := 0;
      Buf (Last + 12) := 0;
      Last := Last + 12;
      Writer.Append_IDB (Buf, Last, Error => Error);

      Cur := Reader.First (Buf'First);
      for I in 1 .. 6 loop
         Reader.Next (Buf (Buf'First .. Last), Cur, Curr);
         exit when Curr.Error /= None;
         Count := Count + 1;
         if Curr.Kind = Kind_Unknown then
            Seen_Unknown := True;
         end if;
         exit when Cur.At_End;
      end loop;
      Check ("unknown skipped, 3 blocks", Count = 3 and Seen_Unknown);
   end;

   if Fail = 0 then
      Put_Line ("PASS test_malformed");
   else
      Put_Line ("FAIL test_malformed:" & Fail'Image);
      raise Program_Error with "test failures";
   end if;
end Test_Malformed;
