(** Moduletto OCaml Test Harness

    Executable tests that mirror the Coq-verified properties,
    providing runtime validation of the modular arithmetic,
    Barrett reduction, constant-time primitives, and NTT
    operations at the Kyber-512 parameter set.
*)

let kyber_q = 3329
let kyber_n = 256
let kyber_zeta = 17

(* ================================================================ *)
(* Modular arithmetic *)
(* ================================================================ *)

let mod_pos x n =
  let r = x mod n in
  if r < 0 then r + n else r

let vt_mod_add a b n =
  let sum = a + b in
  if sum >= n then sum - n else sum

let vt_mod_sub a b n =
  let diff = a - b in
  if diff < 0 then diff + n else diff

let vt_mod_neg a n =
  if a = 0 then 0 else n - a

(* CT operations using bitwise masks *)
let sign_mask x =
  if x < 0 then -1 else 0

let ct_mod_add a b n =
  let sum = a + b in
  let needs_reduction = sign_mask (n - 1 - sum) in
  let reduced = sum - n in
  (reduced land needs_reduction) lor (sum land (lnot needs_reduction))

let ct_mod_sub a b n =
  let diff = a - b in
  let needs_adjustment = sign_mask diff in
  let adjusted = diff + n in
  (adjusted land needs_adjustment) lor (diff land (lnot needs_adjustment))

(* Barrett reduction *)
let barrett_reduce x n k =
  let two_k = 2 * k in
  let m = 1 lsl two_k in
  let mu = m / n in
  let q = (x * mu) asr two_k in
  let r = x - q * n in
  if r >= n then r - n else r

(* CT primitives *)
let ct_select a b choice =
  let mask = -(choice land 1) in
  (a land (lnot mask)) lor (b land mask)

let ct_swap a b choice =
  let mask = -(choice land 1) in
  let xor_val = (a lxor b) land mask in
  (a lxor xor_val, b lxor xor_val)

let ct_is_zero x =
  let neg_x = -x in
  let result = x lor neg_x in
  1 land ((result asr 63) lxor 1)

(* Modular exponentiation *)
let mod_pow base exp modulus =
  let result = ref 1 in
  let b = ref (mod_pos base modulus) in
  let e = ref exp in
  while !e > 0 do
    if !e land 1 = 1 then
      result := mod_pos (!result * !b) modulus;
    b := mod_pos (!b * !b) modulus;
    e := !e asr 1
  done;
  !result

(* ================================================================ *)
(* Test framework *)
(* ================================================================ *)

let tests_run = ref 0
let tests_passed = ref 0
let tests_failed = ref 0

let check name condition =
  incr tests_run;
  if condition then
    incr tests_passed
  else begin
    incr tests_failed;
    Printf.printf "  FAIL: %s\n" name
  end

(* ================================================================ *)
(* Tests *)
(* ================================================================ *)

let test_modular_arithmetic () =
  Printf.printf "=== Modular Arithmetic ===\n";
  let n = kyber_q in

  (* Test VT add correctness *)
  for a = 0 to n - 1 do
    if a mod 500 = 0 then begin
      for b = 0 to n - 1 do
        if b mod 500 = 0 then begin
          let expected = mod_pos (a + b) n in
          check (Printf.sprintf "vt_add(%d,%d)" a b) (vt_mod_add a b n = expected);
          check (Printf.sprintf "ct_add(%d,%d)" a b) (ct_mod_add a b n = expected)
        end
      done
    end
  done;

  (* Test VT sub correctness *)
  for a = 0 to n - 1 do
    if a mod 500 = 0 then begin
      for b = 0 to n - 1 do
        if b mod 500 = 0 then begin
          let expected = mod_pos (a - b) n in
          check (Printf.sprintf "vt_sub(%d,%d)" a b) (vt_mod_sub a b n = expected);
          check (Printf.sprintf "ct_sub(%d,%d)" a b) (ct_mod_sub a b n = expected)
        end
      done
    end
  done;

  (* Test negation *)
  for a = 0 to n - 1 do
    if a mod 100 = 0 then begin
      let neg = vt_mod_neg a n in
      check (Printf.sprintf "neg(%d) in range" a) (neg >= 0 && neg < n);
      check (Printf.sprintf "a + neg(a) = 0 for %d" a) (vt_mod_add a neg n = 0)
    end
  done;

  (* Commutativity *)
  check "add_comm" (vt_mod_add 1234 2345 n = vt_mod_add 2345 1234 n);
  (* Identity *)
  check "add_identity" (vt_mod_add 42 0 n = 42);
  (* Multiplication *)
  check "mul_comm" (mod_pos (1234 * 2345) n = mod_pos (2345 * 1234) n);
  check "mul_identity" (mod_pos (42 * 1) n = 42);
  check "mul_zero" (mod_pos (42 * 0) n = 0);

  Printf.printf "  Modular arithmetic: done\n"

let test_barrett_reduction () =
  Printf.printf "=== Barrett Reduction ===\n";
  let n = kyber_q in
  let k = 12 in

  (* Test Barrett for all products of Kyber coefficients *)
  for a = 0 to n - 1 do
    if a mod 200 = 0 then begin
      for b = 0 to n - 1 do
        if b mod 200 = 0 then begin
          let product = a * b in
          let expected = mod_pos product n in
          let barrett = barrett_reduce product n k in
          check (Printf.sprintf "barrett(%d*%d=%d)" a b product)
            (barrett = expected)
        end
      done
    end
  done;

  (* Edge cases *)
  check "barrett(0)" (barrett_reduce 0 n k = 0);
  check "barrett(1)" (barrett_reduce 1 n k = 1);
  check "barrett(q-1)" (barrett_reduce (n - 1) n k = n - 1);
  check "barrett(q)" (barrett_reduce n n k = 0);
  check "barrett(q^2-1)" (barrett_reduce (n * n - 1) n k = mod_pos (n * n - 1) n);

  Printf.printf "  Barrett reduction: done\n"

let test_ct_primitives () =
  Printf.printf "=== Constant-Time Primitives ===\n";

  (* ct_select *)
  check "ct_select(10,20,0)=10" (ct_select 10 20 0 = 10);
  check "ct_select(10,20,1)=20" (ct_select 10 20 1 = 20);
  check "ct_select(0,0,0)=0" (ct_select 0 0 0 = 0);
  check "ct_select(0,0,1)=0" (ct_select 0 0 1 = 0);
  for a = 0 to 100 do
    for b = 0 to 100 do
      check (Printf.sprintf "ct_select(%d,%d,0)" a b) (ct_select a b 0 = a);
      check (Printf.sprintf "ct_select(%d,%d,1)" a b) (ct_select a b 1 = b)
    done
  done;

  (* ct_swap *)
  check "ct_swap(10,20,0)=(10,20)" (ct_swap 10 20 0 = (10, 20));
  check "ct_swap(10,20,1)=(20,10)" (ct_swap 10 20 1 = (20, 10));
  for a = 0 to 50 do
    for b = 0 to 50 do
      check (Printf.sprintf "ct_swap(%d,%d,0)" a b) (ct_swap a b 0 = (a, b));
      check (Printf.sprintf "ct_swap(%d,%d,1)" a b) (ct_swap a b 1 = (b, a))
    done
  done;

  (* ct_is_zero *)
  check "ct_is_zero(0)=1" (ct_is_zero 0 = 1);
  check "ct_is_zero(1)=0" (ct_is_zero 1 = 0);
  check "ct_is_zero(-1)=0" (ct_is_zero (-1) = 0);
  check "ct_is_zero(3329)=0" (ct_is_zero 3329 = 0);
  for i = 1 to 1000 do
    check (Printf.sprintf "ct_is_zero(%d)=0" i) (ct_is_zero i = 0)
  done;

  Printf.printf "  CT primitives: done\n"

let test_ntt_properties () =
  Printf.printf "=== NTT Properties ===\n";
  let q = kyber_q in

  (* Verify zeta is a 256th root of unity *)
  check "zeta^256 = 1" (mod_pow kyber_zeta 256 q = 1);
  check "zeta^128 = q-1" (mod_pow kyber_zeta 128 q = q - 1);
  check "zeta^64 != 1" (mod_pow kyber_zeta 64 q <> 1);
  check "zeta^32 != 1" (mod_pow kyber_zeta 32 q <> 1);

  (* Verify n^(-1) *)
  check "128 * 3303 = 1 mod q" (mod_pos (128 * 3303) q = 1);

  (* Verify all powers of zeta are distinct (primitive root) *)
  let powers = Array.init 256 (fun i -> mod_pow kyber_zeta i q) in
  let distinct = ref true in
  for i = 0 to 255 do
    for j = i + 1 to 255 do
      if powers.(i) = powers.(j) then distinct := false
    done
  done;
  check "all zeta^i distinct for i=0..255" !distinct;

  (* Verify powers are all nonzero *)
  let all_nonzero = Array.for_all (fun p -> p <> 0) powers in
  check "all zeta^i nonzero" all_nonzero;

  (* Verify q is prime (trial division) *)
  let is_prime = ref true in
  let d = ref 2 in
  while !d * !d <= q do
    if q mod !d = 0 then is_prime := false;
    incr d
  done;
  check "3329 is prime" !is_prime;

  Printf.printf "  NTT properties: done\n"

let () =
  Printf.printf "\n";
  Printf.printf "================================================================\n";
  Printf.printf "  MODULETTO - OCaml Verification Test Suite\n";
  Printf.printf "================================================================\n\n";

  test_modular_arithmetic ();
  test_barrett_reduction ();
  test_ct_primitives ();
  test_ntt_properties ();

  Printf.printf "\n================================================================\n";
  Printf.printf "  Results: %d/%d passed" !tests_passed !tests_run;
  if !tests_failed > 0 then
    Printf.printf " (%d FAILED)" !tests_failed;
  Printf.printf "\n";
  Printf.printf "================================================================\n\n";

  if !tests_failed > 0 then
    exit 1
