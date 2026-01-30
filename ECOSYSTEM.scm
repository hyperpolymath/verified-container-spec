;; SPDX-License-Identifier: PMPL-1.0-or-later
;; ECOSYSTEM.scm — verified-container-spec's position in the hyperpolymath ecosystem
;; Format: hyperpolymath/ECOSYSTEM.scm specification

(ecosystem
  (version . "1.0.0")
  (schema-version . "1.0")

  (name . "verified-container-spec")
  (display-name . "Verified Container Specification")
  (ascii-safe . "verified-container-spec")

  (type . "protocol-specification")
  (purpose . "Attestation and verification protocol for supply-chain-verified containers")

  (language-identity
    (primary . ((asciidoc . "Specification prose")
                (json-schema . "Data schemas")
                (nickel . "Policy contracts")))
    (paradigms . (specification
                  protocol-design
                  formal-contracts)))

  (position-in-ecosystem
    (role . "protocol-authority")
    (layer . "specification")
    (description . "verified-container-spec is the single source of truth for the
                    container verification protocol. All implementations (Vörðr,
                    Svalinn, Cerro Torre) conform to this specification. It defines
                    attestation formats, trust models, and verification semantics."))

  (related-projects
    ((project (name . "vordr")
              (relationship . "implementer")
              (role . "verifier")
              (integration . "Implements verification logic per this spec")
              (url . "https://github.com/hyperpolymath/vordr")))

    ((project (name . "svalinn")
              (relationship . "implementer")
              (role . "gateway")
              (integration . "Validates requests against this spec at the edge")
              (url . "https://github.com/hyperpolymath/svalinn")))

    ((project (name . "cerro-torre")
              (relationship . "implementer")
              (role . "producer")
              (integration . "Produces attestations conforming to this spec")
              (url . "https://github.com/hyperpolymath/cerro-torre")))

    ((project (name . "oblibeny")
              (relationship . "implementer")
              (role . "orchestrator")
              (integration . "Coordinates verified deployments per this spec")
              (url . "https://github.com/hyperpolymath/oblibeny")))

    ((project (name . "sigstore")
              (relationship . "external-standard")
              (integration . "Attestation signing format (Sigstore bundles)")
              (url . "https://sigstore.dev")))

    ((project (name . "in-toto")
              (relationship . "external-standard")
              (integration . "Supply chain attestation format")
              (url . "https://in-toto.io")))

    ((project (name . "SLSA")
              (relationship . "external-standard")
              (integration . "Supply chain security levels framework")
              (url . "https://slsa.dev")))

    ((project (name . "rhodium-standard")
              (relationship . "sibling-standard")
              (integration . "Repository compliance standard")))

    ((project (name . "git-hud")
              (relationship . "infrastructure")
              (integration . "Repository management tooling"))))

  (what-this-is
    "verified-container-spec is a protocol specification that defines:"
    (items
      "Attestation bundle format for container provenance"
      "Trust store configuration and management"
      "Verification protocol and decision semantics"
      "Conformance requirements for producers and consumers"
      "Test vectors for implementation validation"))

  (what-this-is-not
    "verified-container-spec is not:"
    (items
      "An implementation (see Vörðr, Svalinn, Cerro Torre)"
      "A container runtime"
      "A build system"
      "A CI/CD tool"))

  (contents
    ((directory . "spec/")
     (description . "Protocol specification documents"))
    ((directory . "schema/")
     (description . "JSON schemas for attestations and configs"))
    ((directory . "conformance/")
     (description . "Conformance test definitions"))
    ((directory . "vectors/")
     (description . "Test vectors for implementations"))
    ((directory . "examples/")
     (description . "Example attestations and configurations")))

  (implementer-roles
    ((role . "producer")
     (description . "Creates attestations (e.g., Cerro Torre)")
     (requirements . "Must generate valid attestation bundles per schema/"))
    ((role . "verifier")
     (description . "Validates attestations (e.g., Vörðr)")
     (requirements . "Must correctly accept/reject per conformance/"))
    ((role . "gateway")
     (description . "Gates operations on verification (e.g., Svalinn)")
     (requirements . "Must enforce policy decisions from verifier"))
    ((role . "orchestrator")
     (description . "Coordinates verified deployments (e.g., Oblibeny)")
     (requirements . "Must only deploy verified artifacts")))

  (standards-compliance
    ((standard . "RSR")
     (status . "compliant"))
    ((standard . "Sigstore")
     (status . "aligned"))
    ((standard . "in-toto")
     (status . "aligned"))
    ((standard . "SLSA")
     (status . "aligned"))))
