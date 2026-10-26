--  Copyright 2026 Ryan
--  SPDX-License-Identifier: Apache-2.0

pragma SPARK_Mode (On);

with Pcapng_In_Ada; use Pcapng_In_Ada;
with Pcapng_In_Ada.Blocks; use Pcapng_In_Ada.Blocks;
with Pcapng_In_Ada.SHB;

package body Pcapng_In_Ada.Stream is

   procedure Consume
     (S          : in out State;
      Buf        : Byte_Buffer;
      First      : Natural;
      Last       : Natural;
      Consumed   : out Natural;
      Error      : out Error_Kind;
      Blocks_Seen : out Natural)
   is
      P     : Natural := First;
      Seen  : Natural := 0;
      Hdr   : Block_Header;
      H_Nx  : Natural;
      H_Err : Error_Kind;
      Sh    : SHB.SHB_View;
      Sh_Nx : Natural;
      Sh_Er : Error_Kind;
   begin
      Consumed := 0;
      Blocks_Seen := 0;
      Error := None;

      if First < Buf'First or else Last > Buf'Last or else First > Last + 1 then
         Error := Bad_Length;
         return;
      end if;
      if First > Last then
         return;
      end if;

      --  Constrain the whole walk to First .. Last: fit and trailer
      --  checks inside Parse_* must see the window edge, not the
      --  caller's larger buffer. Otherwise a block is consumed past
      --  Last and the next feed restarts mid-block. The slice keeps
      --  absolute indices, so views stay valid against Buf too.
      declare
         Img : Byte_Buffer renames Buf (First .. Last);
      begin
      for I in 1 .. 1_000_000 loop
         pragma Loop_Invariant (P >= First);
         pragma Loop_Invariant (Seen < I);
         exit when P > Last;
         if P < Img'First or else P > Img'Last then
            exit;
         end if;
         --  Need at least an envelope to decide anything.
         if Last - P + 1 < Min_Block_Size then
            exit;  --  truncated tail: caller retains it
         end if;
         if not S.Started then
            SHB.Parse_SHB (Img, P, Sh, Sh_Nx, Sh_Er);
            if Sh_Er = Truncated then
               exit;  --  partial SHB at chunk edge
            elsif Sh_Er /= None then
               Error := Sh_Er;
               Consumed := P - First;
               Blocks_Seen := Seen;
               return;
            end if;
            S.Order := Sh.Order;
            S.Started := True;
            P := Sh_Nx;
            Seen := (if Seen < Natural'Last then Seen + 1 else Seen);
            if S.Count < Natural'Last then
               S.Count := S.Count + 1;
            end if;
         else
            Parse_Header (Img, P, S.Order, Hdr, H_Nx, H_Err);
            if H_Err = Truncated then
               exit;  --  partial block at chunk edge
            elsif H_Err /= None then
               --  Byte-order flip at a section restart makes the
               --  header unreadable in the old order: retry as SHB
               --  (magic decides). Keep the original error on failure.
               SHB.Parse_SHB (Img, P, Sh, Sh_Nx, Sh_Er);
               if Sh_Er = Truncated then
                  exit;
               elsif Sh_Er /= None then
                  Error := H_Err;
                  Consumed := P - First;
                  Blocks_Seen := Seen;
                  return;
               else
                  S.Order := Sh.Order;
                  if S.Section < Positive'Last then
                     S.Section := S.Section + 1;
                  end if;
                  P := Sh_Nx;
                  Seen := (if Seen < Natural'Last then Seen + 1 else Seen);
                  if S.Count < Natural'Last then
                     S.Count := S.Count + 1;
                  end if;
               end if;
            else
            if Hdr.Block_Type = SHB_Type then
               SHB.Parse_SHB (Img, P, Sh, Sh_Nx, Sh_Er);
               if Sh_Er = Truncated then
                  exit;
               elsif Sh_Er /= None then
                  Error := Sh_Er;
                  Consumed := P - First;
                  Blocks_Seen := Seen;
                  return;
               end if;
                  S.Order := Sh.Order;
                  if S.Section < Positive'Last then
                     S.Section := S.Section + 1;
                  end if;
                  P := Sh_Nx;
               else
                  P := H_Nx;
               end if;
               Seen := (if Seen < Natural'Last then Seen + 1 else Seen);
               if S.Count < Natural'Last then
                  S.Count := S.Count + 1;
               end if;
            end if;
         end if;
         exit when I = 1_000_000;
      end loop;
      end;  --  Img window

      Consumed := (if P > Last + 1 then Last + 1 else P) - First;
      Blocks_Seen := Seen;
      Error := None;
   end Consume;

   function Complete_Prefix
     (Buf   : Byte_Buffer;
      First : Natural;
      Last  : Natural;
      Order : Byte_Order;
      Started : Boolean) return Natural
   is
      C   : Natural := 0;
   begin
      --  Stateless walk: reuse Consume on a throwaway cursor over a
      --  bounded window. When the input bounds are insane, report 0.
      if First < Buf'First or else Last > Buf'Last or else First > Last + 1 then
         return 0;
      end if;
      if First > Last then
         return 0;
      end if;
      --  Work around SPARK's no-function-call-with-out-params rule by
      --  inlining the same envelope walk here (read-only, no state).
      --  Img constrains every fit check to the window (see Consume).
      declare
         Img : Byte_Buffer renames Buf (First .. Last);
         P     : Natural := First;
         Hdr   : Block_Header;
         H_Nx  : Natural;
         H_Err : Error_Kind;
         Sh    : SHB.SHB_View;
         Sh_Nx : Natural;
         Sh_Er : Error_Kind;
         Ord   : Byte_Order := Order;
         St    : Boolean := Started;
      begin
         for I in 1 .. 1_000_000 loop
            pragma Loop_Invariant (P >= First);
            exit when P > Last;
            if P < Img'First or else P > Img'Last then
               C := P - First;
               return C;
            end if;
            if Last - P + 1 < Min_Block_Size then
               C := P - First;
               return C;
            end if;
            if not St then
               SHB.Parse_SHB (Img, P, Sh, Sh_Nx, Sh_Er);
               if Sh_Er /= None then
                  C := P - First;
                  return C;
               end if;
               Ord := Sh.Order;
               St := True;
               P := Sh_Nx;
            else
               Parse_Header (Img, P, Ord, Hdr, H_Nx, H_Err);
               if H_Err /= None then
                  --  Same byte-order-flip retry as Consume: an SHB in
                  --  the other order is still a whole block.
                  SHB.Parse_SHB (Img, P, Sh, Sh_Nx, Sh_Er);
                  if Sh_Er /= None then
                     C := P - First;
                     return C;
                  end if;
                  Ord := Sh.Order;
                  P := Sh_Nx;
               elsif Hdr.Block_Type = SHB_Type then
                  SHB.Parse_SHB (Img, P, Sh, Sh_Nx, Sh_Er);
                  if Sh_Er /= None then
                     C := P - First;
                     return C;
                  end if;
                  Ord := Sh.Order;
                  P := Sh_Nx;
               else
                  P := H_Nx;
               end if;
            end if;
            exit when I = 1_000_000;
         end loop;
         C := (if P > Last + 1 then Last + 1 else P) - First;
         return C;
      end;
   end Complete_Prefix;

end Pcapng_In_Ada.Stream;
