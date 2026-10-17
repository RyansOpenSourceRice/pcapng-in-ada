--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Example 1: write a minimal pcapng file (SHB + IDB + EPB) to disk.

with Ada.Streams; use Ada.Streams;
with Ada.Streams.Stream_IO; use Ada.Streams.Stream_IO;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Writer;

procedure Write_Sample is
   Buf   : Byte_Buffer (1 .. 4_096) := [others => 0];
   Last  : Natural := Buf'First - 1;
   Error : Error_Kind;
   Frame : Byte_Buffer (1 .. 42) := [others => 16#AB#];
   Out_F : File_Type;
   S     : Stream_Access;
begin
   Writer.Append_SHB (Buf, Last, Error);
   Writer.Append_IDB (Buf, Last, Error => Error);
   Writer.Append_EPB (Buf, Last, 0, 1_700_000_000_000_000, Frame, Error);
   Create (Out_F, Out_File, "sample.pcapng");
   S := Stream (Out_F);
   declare
      Raw : Stream_Element_Array (1 .. Stream_Element_Offset (Last));
   begin
      for I in 1 .. Last loop
         Raw (Stream_Element_Offset (I)) :=
           Stream_Element (Buf (I));
      end loop;
      Stream_Element_Array'Write (S, Raw);
   end;
   Close (Out_F);
end Write_Sample;
