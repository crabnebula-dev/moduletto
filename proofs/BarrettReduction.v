(** * Moduletto: Barrett Reduction Correctness Proofs

    Formal verification that Barrett reduction produces correct results.

    Barrett reduction computes x mod N without division by using
    a precomputed reciprocal mu = floor(2^(2k) / N) where k = ceil(log2(N)).

    The Rust implementation in src/modn_ct.rs:
<<
    let k = 64 - (N - 1).leading_zeros();
    let two_k = k * 2;
    let r = if 3 * k <= 62 {
        // x*mu < 2^(3k) here, so a 64-bit multiply suffices
        let mu = (1_i64 << two_k) / N;
        let q = (x.wrapping_mul(mu)) >> two_k;
        x - q * N
    } else {
        let mu = (1_i128 << two_k) / (N as i128);
        let q = (((x as i128) * mu) >> two_k) as i64;
        x - q * N
    };
    // constant-time conditional subtraction if r >= N
>>

    Both branches compute the same value; the width is chosen at compile time
    from N. The model below is width-agnostic, so the proofs cover both. *)
(** *)
(**
*)

From Stdlib Require Import ZArith.
From Stdlib Require Import Lia.
From Stdlib Require Import Zdiv.

Open Scope Z_scope.

(** ** Barrett reduction model *)

Definition barrett_reduce (x N mu two_k : Z) : Z :=
  let q := (x * mu) / (Z.pow 2 two_k) in
  let r := x - q * N in
  if Z.leb N r then r - N else r.

(** ** Helper: floor division produces remainder *)
Lemma div_mod_bound : forall a b,
  0 < b -> a = b * (a / b) + a mod b /\ 0 <= a mod b < b.
Proof.
  intros. split.
  - apply Z.div_mod. lia.
  - apply Z.mod_pos_bound. lia.
Qed.

(** ** Upper bound: Barrett quotient does not overshoot

    q = floor(x * mu / M) where mu = floor(M/N).
    Since mu*N <= M and q*M <= x*mu, we get q*N <= x.
*)
Lemma barrett_q_upper :
  forall x N M mu,
    0 < N -> 0 < M ->
    mu = M / N ->
    0 <= x ->
    (x * mu) / M * N <= x.
Proof.
  intros x N M mu HN HM Hmu Hx.
  set (q := (x * mu) / M).
  (* q * M <= x * mu *)
  assert (H1: q * M <= x * mu).
  { unfold q.
    destruct (div_mod_bound (x * mu) M HM) as [Heq [Hlo Hhi]]. nia. }
  (* mu * N <= M *)
  assert (H2: mu * N <= M).
  { subst mu.
    destruct (div_mod_bound M N HN) as [Heq [Hlo Hhi]]. nia. }
  (* From q*M <= x*mu and mu*N <= M, nia derives q*N <= x *)
  nia.
Qed.

(** ** Lower bound: Barrett quotient doesn't undershoot by more than 1

    q >= x/N - 1, so r = x - q*N < 2N.
*)
Lemma barrett_q_lower :
  forall x N M mu,
    0 < N -> 0 < M ->
    N * N <= M ->
    mu = M / N ->
    0 <= x ->
    x < N * N ->
    (x * mu) / M >= x / N - 1.
Proof.
  intros x N M mu HN HM HNM Hmu Hx HxNN.
  apply Z.le_ge.
  apply Z.div_le_lower_bound; try lia.
  (* Need: (x/N - 1) * M <= x * mu *)
  subst mu.
  (* Introduce named variables for all division results *)
  set (xq := x / N).
  set (xr := x mod N).
  set (mq := M / N).
  set (mr := M mod N).
  assert (Hx_eq: x = N * xq + xr) by (unfold xq, xr; apply Z.div_mod; lia).
  assert (Hxr_lo: 0 <= xr) by (unfold xr; apply Z.mod_pos_bound; lia).
  assert (Hxr_hi: xr < N) by (unfold xr; apply Z.mod_pos_bound; lia).
  assert (HM_eq: M = N * mq + mr) by (unfold mq, mr; apply Z.div_mod; lia).
  assert (Hmr_lo: 0 <= mr) by (unfold mr; apply Z.mod_pos_bound; lia).
  assert (Hmr_hi: mr < N) by (unfold mr; apply Z.mod_pos_bound; lia).
  assert (Hxq_lo: 0 <= xq) by (unfold xq; apply Z.div_pos; lia).
  assert (Hxq_hi: xq < N) by (unfold xq; apply Z.div_lt_upper_bound; lia).
  assert (Hmq_lo: 0 <= mq) by (unfold mq; apply Z.div_pos; lia).
  (* Now rewrite everything in terms of named variables, no more / or mod *)
  (* Goal: (xq - 1) * M <= x * mq *)
  (* i.e.: (xq - 1) * (N * mq + mr) <= (N * xq + xr) * mq *)
  rewrite Hx_eq. rewrite HM_eq.
  (* Expand: (xq - 1) * (N * mq + mr) <= (N * xq + xr) * mq *)
  (* RHS - LHS = xr*mq + mr + N*mq - xq*mr *)
  (*           = xr*mq + mr*(1 - xq) + N*mq *)
  (* Since N*mq >= 0 and xr*mq >= 0, we need mr*(1 - xq) + N*mq >= 0 *)
  (* i.e., N*mq >= mr*(xq - 1) *)
  (* Since mr < N and xq < N: mr*(xq-1) < N*(N-1) *)
  (* And N*mq >= N (when mq >= 1, which holds since M >= N) *)
  (* Actually mq = M/N and M > 0 and N > 0. If M < N then mq = 0 *)
  (* but then mr = M and the bound still holds *)
  assert (Hdiff: (N * xq + xr) * mq - (xq - 1) * (N * mq + mr) =
                 xr * mq + mr * (1 - xq) + N * mq) by ring.
  assert (Hmq_pos: N <= mq).
  { unfold mq. apply Z.div_le_lower_bound; lia. }
  (* Now: xr*mq + mr*(1-xq) + N*mq >= 0 *)
  (* mr*(1-xq) >= -mr*(N-1) >= -(N-1)^2 *)
  (* N*mq >= N*1 = N *)
  (* xr*mq >= 0 *)
  (* So sum >= N - (N-1)^2 + 0. That can be negative for large N. *)
  (* But also: xr*mq >= 0 and N*mq >= N, so sum >= N + mr - mr*xq *)
  (* = N + mr*(1 - xq). Since xq <= N-1: mr*(1-xq) >= mr*(2-N) >= -(N-1)*(N-2) *)
  (* N >= N. Need: N >= (N-1)*(N-2) - mr + mr*xq ... *)
  (* This is getting complicated. Let's just provide the explicit expansion to nia *)
  (* With mq >= N, nia can handle this *)
  nia.
Qed.

(** ** The Barrett remainder is in [0, 2N) before the final correction *)
Lemma barrett_remainder_bound :
  forall x N k mu,
    0 < N ->
    0 < k ->
    N <= Z.pow 2 k ->
    mu = Z.pow 2 (2 * k) / N ->
    0 <= x ->
    x < N * N ->
    let q := (x * mu) / Z.pow 2 (2 * k) in
    let r := x - q * N in
    0 <= r /\ r < 2 * N.
Proof.
  intros x N k mu HN Hk HNbound Hmu Hx0 HxNN.
  set (M := Z.pow 2 (2 * k)).
  assert (HM_pos: 0 < M) by (unfold M; apply Z.pow_pos_nonneg; lia).
  assert (HNN_le_M: N * N <= M).
  { unfold M.
    assert (H2k: Z.pow 2 (2 * k) = Z.pow 2 k * Z.pow 2 k).
    { rewrite <- Z.pow_add_r; try lia. f_equal. lia. }
    rewrite H2k.
    apply Z.mul_le_mono_nonneg; lia. }
  split.
  - (* r >= 0 *)
    assert (H := barrett_q_upper x N M mu HN HM_pos Hmu Hx0). lia.
  - (* r < 2N *)
    assert (Hq_ge := barrett_q_lower x N M mu HN HM_pos HNN_le_M Hmu Hx0 HxNN).
    (* q >= x/N - 1 means q*N >= (x/N - 1)*N *)
    assert (HxdivN_bound: (x / N) * N >= x - (N - 1)).
    { destruct (div_mod_bound x N HN) as [Hx_eq [Hxm_lo Hxm_hi]]. nia. }
    nia.
Qed.

(** ** Barrett reduction with conditional subtraction produces correct result *)
Theorem barrett_reduce_correct :
  forall x N k mu,
    0 < N ->
    0 < k ->
    N <= Z.pow 2 k ->
    mu = Z.pow 2 (2 * k) / N ->
    0 <= x ->
    x < N * N ->
    barrett_reduce x N mu (2 * k) = x mod N.
Proof.
  intros x N k mu HN Hk HNbound Hmu Hx0 HxNN.
  unfold barrett_reduce.
  set (M := Z.pow 2 (2 * k)).
  set (q := (x * mu) / M).
  set (r := x - q * N).
  assert (Hbounds: 0 <= r /\ r < 2 * N).
  { apply (barrett_remainder_bound x N k mu); auto. }
  destruct (Z.leb N r) eqn:Hle.
  - apply Z.leb_le in Hle.
    unfold r, q.
    apply (Zmod_unique x N ((x * mu) / M + 1) (x - (x * mu) / M * N - N)); lia.
  - apply Z.leb_gt in Hle.
    unfold r, q.
    apply (Zmod_unique x N ((x * mu) / M) (x - (x * mu) / M * N)); lia.
Qed.

(** ** The result is in canonical range [0, N) *)
Theorem barrett_reduce_in_range :
  forall x N k mu,
    0 < N ->
    0 < k ->
    N <= Z.pow 2 k ->
    mu = Z.pow 2 (2 * k) / N ->
    0 <= x ->
    x < N * N ->
    0 <= barrett_reduce x N mu (2 * k) /\ barrett_reduce x N mu (2 * k) < N.
Proof.
  intros.
  rewrite barrett_reduce_correct; auto.
  split.
  - apply Z.mod_pos_bound. lia.
  - apply Z.mod_pos_bound. lia.
Qed.

(** ** Kyber-specific instantiation: N = 3329, k = 12 *)

Theorem barrett_kyber_correct :
  forall x,
    0 <= x ->
    x < 3329 * 3329 ->
    barrett_reduce x 3329 (Z.pow 2 24 / 3329) 24 = x mod 3329.
Proof.
  intros.
  change 24 with (2 * 12).
  apply barrett_reduce_correct; try lia.
Qed.

(** * Rounding Barrett reduction (the NTT kernel)

    The NTT in src/ntt.rs does not use the floor-Barrett reduction above.
    Reducing to the canonical range [0, N) after every operation costs a
    conditional fixup, and with q = 3329 in a 64-bit register there are ~50
    spare bits, so the kernel instead uses a *rounding* Barrett that returns a
    centred representative and never corrects:

<<
    const LAZY_S: u32 = 32;
    const LAZY_MU: i64 = (1_i64 << LAZY_S) / KYBER_Q;

    fn fq_reduce(x: i64) -> i64 {
        let quot = (x.wrapping_mul(LAZY_MU) + (1_i64 << (LAZY_S - 1))) >> LAZY_S;
        x - quot * KYBER_Q
    }
>>

    This section proves the two properties the kernel relies on: the result is
    congruent to the input, and it is bounded by N in absolute value. With no
    conditional correction the operation is branchless, therefore constant-time
    and vectorisable. *)

Definition fq_reduce (x N mu h M : Z) : Z :=
  let quot := (x * mu + h) / M in
  x - quot * N.

(** ** Congruence: the reduction preserves the residue class.

    Immediate — the reduction only ever subtracts a multiple of N. *)
Theorem fq_reduce_congruent :
  forall x N mu h M,
    N <> 0 ->
    (fq_reduce x N mu h M) mod N = x mod N.
Proof.
  intros x N mu h M HN. unfold fq_reduce.
  rewrite Zminus_mod, Z_mod_mult, Z.sub_0_r, Zmod_mod. reflexivity.
Qed.

(** ** Bound: the result lies strictly inside (-N, N).

    Let M = 2^S, h = M/2 the rounding offset, and d = M - mu*N, so that
    0 <= d < N because mu = floor(M/N). Writing e = (x*mu + h) mod M gives
    M*quot = x*mu + h - e, and substituting into r = x - quot*N yields

      r * M = x*d + N*(e - h).

    From |x| < h and 0 <= d <= N-1 we get |x*d| < N*h; from 0 <= e < M = 2h we
    get |N*(e - h)| <= N*h. Hence |r*M| < 2*N*h = N*M, so |r| < N. *)
Theorem fq_reduce_bound :
  forall x N mu h M,
    0 < N ->
    0 < h ->
    2 * h = M ->
    mu = M / N ->
    - h < x < h ->
    - N < fq_reduce x N mu h M < N.
Proof.
  intros x N mu h M HN Hh HM Hmu Hx.
  assert (HM0 : 0 < M) by lia.

  set (num := x * mu + h).
  set (quot := num / M).
  set (e := num mod M).

  assert (He : 0 <= e < M) by (unfold e; apply Z.mod_pos_bound; lia).
  assert (Hdec : num = M * quot + e) by (unfold quot, e; apply Z.div_mod; lia).
  assert (Hmq : M * quot = x * mu + h - e) by (unfold num in Hdec; lia).

  (* d = M - mu*N lies in [0, N) because mu = floor(M/N). *)
  assert (Hd : 0 <= M - mu * N < N).
  { subst mu. split.
    - assert (N * (M / N) <= M) by (apply Z.mul_div_le; lia). nia.
    - assert (Hgt := Z.mul_succ_div_gt M N HN).
      rewrite Z.mul_succ_r in Hgt. nia. }

  (* The reduction unfolds to x - quot*N. *)
  assert (Hunfold : fq_reduce x N mu h M = x - quot * N) by reflexivity.
  rewrite Hunfold.

  (* Key identity: (x - quot*N) * M = x*(M - mu*N) + N*(e - h). *)
  assert (Hkey : (x - quot * N) * M = x * (M - mu * N) + N * (e - h)).
  { ring_simplify. nia. }

  (* Bound the two right-hand terms separately. *)
  assert (Hxd : - (N * h) < x * (M - mu * N) < N * h) by nia.
  assert (Hen : - (N * h) <= N * (e - h) <= N * h) by nia.

  (* Hence |(x - quot*N) * M| < N*M, and M > 0 gives the result. *)
  nia.
Qed.

(** ** Kyber instantiation used by the kernel: N = 3329, S = 32.

    LAZY_MU = 2^32 / 3329 = 1290167, the rounding offset is h = 2^31, and the
    admissible input range is |x| < 2^31. The growth analysis in src/ntt.rs
    gives a maximum multiply input of 784_677_195 in the inverse transform,
    within that range. *)
Theorem fq_reduce_kyber :
  forall x,
    - (2 ^ 31) < x < 2 ^ 31 ->
    - 3329 < fq_reduce x 3329 (2 ^ 32 / 3329) (2 ^ 31) (2 ^ 32) < 3329.
Proof.
  intros x Hx.
  apply (fq_reduce_bound x 3329 (2 ^ 32 / 3329) (2 ^ 31) (2 ^ 32));
    try reflexivity; try lia.
Qed.

(** ** The reciprocal really is 1290167, matching LAZY_MU in the Rust source. *)
Theorem lazy_mu_value : 2 ^ 32 / 3329 = 1290167.
Proof. reflexivity. Qed.
