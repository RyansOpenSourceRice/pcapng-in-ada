--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0
--
--  Incremental (streaming) block consumer. The core stays OS-free:
--  callers feed byte slices (file chunks, socket reads) and this
--  package reports how many leading bytes form whole blocks. The
--  caller slides the incomplete tail forward, so a 4 GiB capture
--  parses in a fixed 64 KiB window.

pragma SPARK_Mode (On);

with Pcapng_In_Ada; use Pcapng_In_Ada;

package Pcapng_In_Ada.Stream is

   type State is record
      Order   : Byte_Order;
      Started : Boolean;
      Section : Positive;
      Count   : Natural;
   end record;

   function Init return State is
     ((Order => Little_Endian, Started => False,
       Section => 1, Count => 0));

   --  Walk whole blocks in Buf (First .. Last). Consumed is the
   --  length of the leading whole-block prefix; the tail
   --  (Last - First + 1 - Consumed) is an incomplete block the caller
   --  must retain and prepend to the next feed. Blocks_Seen counts
   --  whole blocks in this call.
   --
   --  Semantic errors (bad magic/trailer/length) stop the walk with
   --  Error set; truncation of the tail is NOT an error (it is the
   --  normal chunk boundary).
   procedure Consume
     (S          : in out State;
      Buf        : Byte_Buffer;
      First      : Natural;
      Last       : Natural;
      Consumed   : out Natural;
      Error      : out Error_Kind;
      Blocks_Seen : out Natural);

   --  Pure helper: length of the leading whole-block run without
   --  updating any state (same walk, throwaway cursor).
   function Complete_Prefix
     (Buf   : Byte_Buffer;
      First : Natural;
      Last  : Natural;
      Order : Byte_Order;
      Started : Boolean) return Natural;

end Pcapng_In_Ada.Stream;
