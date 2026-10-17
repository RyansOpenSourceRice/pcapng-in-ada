--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Example 2: dump block inventory of a pcapng file given on the command
--  line. Usage: read_dump <file.pcapng>

with Ada.Text_IO; use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Ada.Streams.Stream_IO;
with Ada.Streams; use Ada.Streams;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Reader;

procedure Read_Dump is
   Buf : Byte_Buffer (1 .. 16#200000#) := [others => 0];
   Got : Natural := 0;
begin
   if Argument_Count < 1 then
      Put_Line ("usage: read_dump <file.pcapng>");
      return;
   end if;
   declare
      F : Ada.Streams.Stream_IO.File_Type;
      S : Ada.Streams.Stream_IO.Stream_Access;
   begin
      Ada.Streams.Stream_IO.Open (F, Ada.Streams.Stream_IO.In_File, Argument (1));
      S := Ada.Streams.Stream_IO.Stream (F);
      while not Ada.Streams.Stream_IO.End_Of_File (F) and then Got < Buf'Last loop
         declare
            Item : Stream_Element_Array (1 .. 1);
            Last_E : Stream_Element_Offset;
         begin
            Ada.Streams.Stream_IO.Read (F, Item, Last_E);
            exit when Last_E < 1;
            Got := Got + 1;
            Buf (Got) := Unsigned_8 (Item (1));
         end;
      end loop;
      Ada.Streams.Stream_IO.Close (F);
   end;
   if Got < Min_Block_Size then
      Put_Line ("file too small");
      return;
   end if;
   declare
      Cur  : Reader.Cursor := Reader.First (Buf'First);
      Curr : Reader.Current_Block;
      N    : Natural := 0;
   begin
      loop
         Reader.Next (Buf (Buf'First .. Got), Cur, Curr);
         exit when Curr.Error /= None;
         N := N + 1;
         Put_Line (N'Image & " kind=" & Curr.Kind'Image
                   & " type=" & Curr.Block_Type'Image
                   & " len=" & Curr.Total_Length'Image);
         exit when Cur.At_End;
         exit when N > 10_000;
      end loop;
      if Curr.Error /= None then
         Put_Line ("stop: " & Curr.Error'Image);
      end if;
   end;
end Read_Dump;
