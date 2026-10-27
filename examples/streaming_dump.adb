--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Example 4: constant-memory block inventory. Reads the file in
--  chunks, consumes whole blocks via Pcapng_In_Ada.Stream, slides
--  the incomplete tail forward. A large capture never needs more
--  than the 128 KiB window.

with Ada.Text_IO; use Ada.Text_IO;
with Ada.Command_Line; use Ada.Command_Line;
with Ada.Streams.Stream_IO;
with Ada.Streams; use Ada.Streams;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Stream;

procedure Streaming_Dump is
   Window_Cap : constant := 131_072;
   Buf  : Byte_Buffer (1 .. Window_Cap) := [others => 0];
   Fill : Natural := 0;
   Total_Blocks : Natural := 0;
   Total_Bytes  : Natural := 0;
   S : Stream.State := Stream.Init;
begin
   if Argument_Count < 1 then
      Put_Line ("usage: streaming_dump <file.pcapng>");
      return;
   end if;
   declare
      F : Ada.Streams.Stream_IO.File_Type;
   begin
      Ada.Streams.Stream_IO.Open
        (F, Ada.Streams.Stream_IO.In_File, Argument (1));
      loop
         --  Top up the window from disk.
         while Fill < Window_Cap
           and then not Ada.Streams.Stream_IO.End_Of_File (F)
         loop
            declare
               Want : constant Natural :=
                 Natural'Min (4_096, Window_Cap - Fill);
               Item : Stream_Element_Array
                 (1 .. Stream_Element_Offset (Want));
               Last_E : Stream_Element_Offset;
            begin
               Ada.Streams.Stream_IO.Read (F, Item, Last_E);
               exit when Last_E < 1;
               for I in 1 .. Natural (Last_E) loop
                  Fill := Fill + 1;
                  Buf (Fill) := Unsigned_8 (Item (Stream_Element_Offset (I)));
               end loop;
               exit when Natural (Last_E) < Want;
            end;
         end loop;
         exit when Fill = 0;
         declare
            Consumed : Natural;
            Err      : Error_Kind;
            Seen     : Natural;
         begin
            --  Only the filled prefix is image; the rest of the window
            --  is zero padding and must not be parsed.
            Stream.Consume (S, Buf (Buf'First .. Fill),
                            Buf'First, Fill,
                            Consumed, Err, Seen);
            if Err /= None then
               Put_Line ("stop: " & Err'Image
                         & " after" & Total_Blocks'Image & " blocks");
               exit;
            end if;
            Total_Blocks := Total_Blocks + Seen;
            Total_Bytes := Total_Bytes + Consumed;
            if Consumed = 0 then
               if Ada.Streams.Stream_IO.End_Of_File (F) then
                  Put_Line ("stop: truncated tail ("
                            & Fill'Image & " bytes remain )");
                  exit;
               elsif Fill = Window_Cap then
                  Put_Line ("stop: single block exceeds window");
                  exit;
               end if;
            else
               declare
                  Tail : constant Natural := Fill - Consumed;
               begin
                  for I in 1 .. Tail loop
                     Buf (I) := Buf (Consumed + I);
                  end loop;
                  Fill := Tail;
               end;
            end if;
            exit when Fill = 0
              and then Ada.Streams.Stream_IO.End_Of_File (F);
         end;
         exit when Ada.Streams.Stream_IO.End_Of_File (F) and then Fill = 0;
      end loop;
      Ada.Streams.Stream_IO.Close (F);
   end;
   Put_Line ("blocks:" & Total_Blocks'Image
             & " bytes:" & Total_Bytes'Image
             & " sections:" & S.Section'Image);
end Streaming_Dump;
