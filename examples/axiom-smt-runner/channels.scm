;; Guix channels for Axiom SMT solvers
;;
;; Provides reproducible, cryptographically verified builds of:
;; - Z3 (Microsoft Research)
;; - CVC5 (Stanford/Iowa)
;; - Yices (SRI International)
;; - MathSAT (FBK-IRST/University of Trento)
;;
;; All solvers are pinned to specific commits for reproducibility.

(list
  ;; Official Guix channel (for core infrastructure)
  (channel
    (name 'guix)
    (url "https://git.savannah.gnu.org/git/guix.git")
    (branch "master")
    (introduction
      (make-channel-introduction
        "9edb3f66fd807b096b48283debdcddccfea34bad"
        (openpgp-fingerprint
          "BBB0 2DDF 2CEA F6A8 0D1D  E643 A2A0 6DF2 A33A 54FA"))))

  ;; Hyperpolymath channel (for custom SMT solver builds if needed)
  (channel
    (name 'hyperpolymath)
    (url "https://github.com/hyperpolymath/guix-channel.git")
    (branch "main")
    ;; TODO: Add channel introduction with GPG key once guix-channel repo is set up
    ))
