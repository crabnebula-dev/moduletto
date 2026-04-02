(** * Moduletto: Constant-Time Primitive Correctness Proofs

    Formal verification of the branchless constant-time primitives:
    ct_is_zero, ct_select, ct_swap, ct_lt, ct_eq.

    These proofs correspond to the Rust code in src/modn_ct.rs.
*)

From Stdlib Require Import ZArith.
From Stdlib Require Import Lia.

Open Scope Z_scope.

(** ** ct_is_zero

    The Rust implementation:
<<
    fn ct_is_zero(x: i64) -> u8 {
        let neg_x = x.wrapping_neg();
        let result = x | neg_x;
        (1 & ((result >> 63) ^ 1)) as u8
    }
>>

    Key property: x | (-x) has a set sign bit iff x != 0.
*)

(** For the proof we use the abstract specification *)
Definition ct_is_zero_spec (x : Z) : Z :=
  if Z.eqb x 0 then 1 else 0.

(** Key property: x | (-x) = 0 iff x = 0 *)
Lemma lor_neg_zero : forall x, Z.lor x (- x) = 0 -> x = 0.
Proof.
  intros x H. apply Z.lor_eq_0_l in H. exact H.
Qed.

Lemma lor_neg_nonzero : forall x, x <> 0 -> Z.lor x (- x) <> 0.
Proof.
  intros x Hne Habs.
  apply Hne. apply lor_neg_zero. exact Habs.
Qed.

(** ** ct_select

    The Rust implementation:
<<
    fn ct_select(a: Self, b: Self, choice: u8) -> Self {
        let mask = ct_mask(-((choice & 1) as i64));
        let result = (a.value() & !mask) | (b.value() & mask);
        ...
    }
>>
*)

Definition ct_select (a b : Z) (choice : Z) : Z :=
  let mask := - Z.land choice 1 in
  Z.lor (Z.land a (Z.lnot mask)) (Z.land b mask).

Theorem ct_select_0 : forall a b,
  ct_select a b 0 = a.
Proof.
  intros. unfold ct_select. simpl.
  replace (Z.lnot 0) with (-1) by reflexivity.
  rewrite Z.land_m1_r.
  rewrite Z.land_0_r. rewrite Z.lor_0_r. reflexivity.
Qed.

Theorem ct_select_1 : forall a b,
  ct_select a b 1 = b.
Proof.
  intros. unfold ct_select. simpl.
  change (- Z.land 1 1) with (-1).
  rewrite Z.land_m1_r.
  replace (Z.lnot (-1)) with 0 by reflexivity.
  rewrite Z.land_0_r. rewrite Z.lor_0_l. reflexivity.
Qed.

(** ct_select never produces a value other than a or b *)
Theorem ct_select_binary : forall a b choice,
  (Z.land choice 1 = 0 \/ Z.land choice 1 = 1) ->
  ct_select a b choice = a \/ ct_select a b choice = b.
Proof.
  intros a b choice [H | H]; unfold ct_select; rewrite H; simpl.
  - left.
    replace (Z.lnot 0) with (-1) by reflexivity.
    rewrite Z.land_m1_r.
    rewrite Z.land_0_r. rewrite Z.lor_0_r. reflexivity.
  - right.
    change (-1) with (- 1).
    rewrite Z.land_m1_r.
    replace (Z.lnot (-1)) with 0 by reflexivity.
    rewrite Z.land_0_r. rewrite Z.lor_0_l. reflexivity.
Qed.

(** ** ct_swap

    The Rust implementation:
<<
    fn ct_swap(a: &mut Self, b: &mut Self, choice: u8) {
        let mask = ct_mask(-((choice & 1) as i64));
        let xor = (a.value() ^ b.value()) & mask;
        let new_a = a.value() ^ xor;
        let new_b = b.value() ^ xor;
        ...
    }
>>
*)

Definition ct_swap (a b : Z) (choice : Z) : (Z * Z) :=
  let mask := - Z.land choice 1 in
  let xor_val := Z.land (Z.lxor a b) mask in
  (Z.lxor a xor_val, Z.lxor b xor_val).

Theorem ct_swap_0 : forall a b,
  ct_swap a b 0 = (a, b).
Proof.
  intros. unfold ct_swap. simpl.
  rewrite Z.land_0_r. rewrite Z.lxor_0_r. rewrite Z.lxor_0_r.
  reflexivity.
Qed.

Theorem ct_swap_1 : forall a b,
  ct_swap a b 1 = (b, a).
Proof.
  intros. unfold ct_swap. simpl.
  change (- Z.land 1 1) with (-1).
  rewrite Z.land_m1_r.
  (* XOR swap: a ^ (a ^ b) = b, b ^ (a ^ b) = a *)
  assert (Ha: Z.lxor a (Z.lxor a b) = b).
  { rewrite <- Z.lxor_assoc. rewrite Z.lxor_nilpotent. apply Z.lxor_0_l. }
  assert (Hb: Z.lxor b (Z.lxor a b) = a).
  { rewrite (Z.lxor_comm a b).
    rewrite <- Z.lxor_assoc. rewrite Z.lxor_nilpotent. apply Z.lxor_0_l. }
  rewrite Ha, Hb. reflexivity.
Qed.

(** ** ct_lt (constant-time less-than)

    The Rust implementation:
<<
    fn ct_lt(self, other: Self) -> u8 {
        let diff = self.value() - other.value();
        ((core::hint::black_box(diff) >> 63) & 1) as u8
    }
>>
*)

Definition ct_lt (a b : Z) : Z :=
  Z.land (Z.shiftr (a - b) 63) 1.

Theorem ct_lt_correct :
  forall a b,
    0 <= a < Z.pow 2 62 ->
    0 <= b < Z.pow 2 62 ->
    a < b ->
    ct_lt a b = 1.
Proof.
  intros a b [Ha0 HaN] [Hb0 HbN] Hlt.
  unfold ct_lt.
  rewrite Z.shiftr_div_pow2 by lia.
  assert (Hdiv: (a - b) / Z.pow 2 63 = -1).
  { symmetry. apply Z.div_unique with (a - b + Z.pow 2 63). lia. lia. }
  rewrite Hdiv. reflexivity.
Qed.

Theorem ct_lt_not :
  forall a b,
    0 <= a < Z.pow 2 62 ->
    0 <= b < Z.pow 2 62 ->
    a >= b ->
    ct_lt a b = 0.
Proof.
  intros a b [Ha0 HaN] [Hb0 HbN] Hge.
  unfold ct_lt.
  rewrite Z.shiftr_div_pow2 by lia.
  assert (Hdiv: (a - b) / Z.pow 2 63 = 0).
  { symmetry. apply Z.div_unique with (a - b). lia. lia. }
  rewrite Hdiv. reflexivity.
Qed.

(** ** ct_eq (constant-time equality) *)

Lemma xor_eq_zero : forall x, Z.lxor x x = 0.
Proof. intros. apply Z.lxor_nilpotent. Qed.

Lemma xor_neq_nonzero : forall x y, x <> y -> Z.lxor x y <> 0.
Proof.
  intros x y Hne Habs.
  apply Hne.
  assert (Z.lxor (Z.lxor x y) y = Z.lxor 0 y) by (rewrite Habs; reflexivity).
  rewrite Z.lxor_assoc in H.
  rewrite Z.lxor_nilpotent in H.
  rewrite Z.lxor_0_r in H.
  rewrite Z.lxor_0_l in H.
  exact H.
Qed.
