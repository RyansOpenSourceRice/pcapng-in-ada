--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Round-trip test: write SHB + IDB + 2xEPB, read back, verify fields.

with Ada.Text_IO; use Ada.Text_IO;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Writer;
with Pcapng_In_Ada.Reader;
with Pcapng_In_Ada.Packet;

procedure Test_Reader is
   Buf   : Byte_Buffer (1 .. 4_096) := [others => 0];
   Last  : Natural := Buf'First - 1;
   Error : Error_Kind;
   Data  : Byte_Buffer (1 .. 14) :=
     [16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#,
      16#08#, 16#00#];
   Cur   : Reader.Cursor := Reader.First (Buf'First);
   Curr  : Reader.Current_Block;
   Count : Natural := 0;
   Fail  : Natural := 0;

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
   Writer.Append_SHB (Buf (1 .. Buf'Last), Last, Error);
   Check ("write shb", Error = None);
   Writer.Append_IDB (Buf (1 .. Buf'Last), Last, Error => Error);
   Check ("write idb", Error = None);
   Writer.Append_EPB
     (Buf (1 .. Buf'Last), Last, 0, 1_700_000_000_000_000, Data, Error);
   Check ("write epb#1", Error = None);
   Writer.Append_EPB
     (Buf (1 .. Buf'Last), Last, 0, 1_700_000_000_000_001, Data, Error);
   Check ("write epb#2", Error = None);

   declare
      Img : Byte_Buffer renames Buf;
   begin
      Cur := Reader.First (Img'First);
      for I in 1 .. 6 loop
         Reader.Next (Img (Img'First .. Last), Cur, Curr);
         exit when Curr.Error /= None;
         Count := Count + 1;
         exit when Cur.At_End;
      end loop;
   end;
   Check ("four blocks walked", Count = 4);

   declare
      View : Packet.EPB_View;
      Nx   : Natural;
      Er   : Error_Kind;
      Found : Boolean := False;
   begin
      --  Re-scan for first EPB and check payload echo.
      Cur := Reader.First (Buf'First);
      for I in 1 .. 6 loop
         Reader.Next (Buf (Buf'First .. Last), Cur, Curr);
         exit when Curr.Error /= None;
         if Curr.Kind = Kind_EPB then
            Packet.Parse_EPB
              (Buf (Buf'First .. Last), Curr.Next - Curr.Total_Length,
               Cur.Order, View, Nx, Er);
            if Er = None
              and then View.Cap_Len = Data'Length
              and then View.Data_Last - View.Data_First + 1 = Data'Length
            then
               Found := True;
            end if;
            exit;
         end if;
         exit when Cur.At_End;
      end loop;
      Check ("epb payload echo", Found);
   end;

   if Fail = 0 then
      Put_Line ("PASS test_reader");
   else
      Put_Line ("FAIL test_reader:" & Fail'Image & " checks failed");
      raise Program_Error with "test failures";
   end if;
end Test_Reader;
