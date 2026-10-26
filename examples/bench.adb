--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Bench: build a ~4 MB image of 14-byte frames, then time the write,
--  the cursor walk, and the chunked stream parse. Prints MB/s and
--  packets/s. Not part of `alr test`; run manually and record the
--  table in README ("Performance").

with Ada.Text_IO; use Ada.Text_IO;
with Ada.Real_Time; use Ada.Real_Time;
with Interfaces; use Interfaces;
with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Writer;
with Pcapng_In_Ada.Reader;
with Pcapng_In_Ada.Stream;

procedure Bench is
   Size : constant := 4 * 1024 * 1024;
   type Big_Buffer is access Byte_Buffer;
   Buf_Ptr : Big_Buffer := new Byte_Buffer (1 .. Size);
   Buf : Byte_Buffer renames Buf_Ptr.all;
   Last : Natural := Buf'First - 1;
   Err  : Error_Kind;
   Fr   : Byte_Buffer (1 .. 14) :=
     [16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#00#, 16#11#, 16#22#, 16#33#, 16#44#, 16#55#,
      16#08#, 16#00#];
   Packets : Natural := 0;
   T0, T1 : Time;
   Ms : Natural;

   function MBs (Bytes : Natural; Elapsed : Time_Span) return Float is
      Usec : constant Float :=
        Float (To_Duration (Elapsed)) * 1_000_000.0;
   begin
      if Usec <= 0.0 then
         return 0.0;
      end if;
      return Float (Bytes) / Usec;
   end MBs;

begin
   Writer.Append_SHB (Buf, Last, Err);
   Writer.Append_IDB (Buf, Last, Error => Err);

   T0 := Clock;
   loop
      Writer.Append_EPB (Buf, Last, 0, Unsigned_64 (Packets), Fr, Err);
      exit when Err /= None;
      Packets := Packets + 1;
   end loop;
   T1 := Clock;
   Ms := Last;
   Put_Line ("write:" & MBs (Ms, T1 - T0)'Image & " MB/s");
   Put_Line ("image bytes:" & Ms'Image & " packets:" & Packets'Image);

   --  Cursor walk.
   declare
      Cur : Reader.Cursor := Reader.First (Buf'First);
      Curr : Reader.Current_Block;
      N : Natural := 0;
      T2 : constant Time := Clock;
   begin
      loop
         Reader.Next (Buf (Buf'First .. Ms), Cur, Curr);
         exit when Curr.Error /= None;
         N := N + 1;
         exit when Cur.At_End;
      end loop;
      T1 := Clock;
      Put_Line ("walk blocks:" & N'Image
                & " packets/s:" & Float'Image
                  (Float (Packets) / Float'Max (0.000_001,
                   Float (To_Duration (T1 - T2))))
                & " MB/s:" & MBs (Ms, T1 - T2)'Image);
   end;

   --  Chunked stream parse (64 KiB feeds).
   declare
      S : Stream.State := Stream.Init;
      P : Natural := Buf'First;
      Seen : Natural := 0;
      T2 : constant Time := Clock;
   begin
      while P <= Ms loop
         declare
            First : constant Natural := P;
            Last_Feed : constant Natural := Natural'Min (Ms, P + 65_535);
            Consumed : Natural;
            E : Error_Kind;
            N : Natural;
         begin
            Stream.Consume (S, Buf (Buf'First .. Ms),
                            First, Last_Feed, Consumed, E, N);
            exit when E /= None;
            Seen := Seen + N;
            exit when Consumed = 0;
            P := First + Consumed;
         end;
      end loop;
      T1 := Clock;
      Put_Line ("stream blocks:" & Seen'Image
                & " MB/s:" & MBs (Ms, T1 - T2)'Image);
   end;
end Bench;
