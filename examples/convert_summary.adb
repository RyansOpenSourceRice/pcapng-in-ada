--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Example 3: count packets and bytes per interface over a file.

with Ada.Text_IO; use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Ada.Streams.Stream_IO;
with Ada.Streams; use Ada.Streams;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Reader;
with Pcapng_In_Ada.Packet;

procedure Convert_Summary is
   Buf : Byte_Buffer (1 .. 16#200000#) := [others => 0];
   Got : Natural := 0;
   Packets : Natural := 0;
   Bytes   : Natural := 0;
begin
   if Argument_Count < 1 then
      Put_Line ("usage: convert_summary <file.pcapng>");
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
   declare
      Cur  : Reader.Cursor := Reader.First (Buf'First);
      Curr : Reader.Current_Block;
   begin
      loop
         Reader.Next (Buf (Buf'First .. Got), Cur, Curr);
         exit when Curr.Error /= None;
         if Curr.Kind = Kind_EPB then
            declare
               V  : Packet.EPB_View;
               Nx : Natural;
               Er : Error_Kind;
               Start : constant Positive :=
                 Curr.Next - Curr.Total_Length;
               B : Byte_Buffer renames Buf;
            begin
               Packet.Parse_EPB
                 (B (B'First .. Got), Start, Cur.Order, V, Nx, Er);
               if Er = None then
                  Packets := Packets + 1;
                  Bytes := Bytes + Natural (V.Cap_Len);
               end if;
            end;
         end if;
         exit when Cur.At_End;
      end loop;
      Put_Line ("packets:" & Packets'Image & " bytes:" & Bytes'Image);
   end;
end Convert_Summary;
