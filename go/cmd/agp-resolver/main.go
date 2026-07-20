package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

type Member struct {
	MemberID string   `json:"member_id"`
	Roles    []string `json:"roles"`
	Weight   int      `json:"weight"`
}

type Rule struct {
	QuorumMinimum                int      `json:"quorum_minimum"`
	AbstentionCountsTowardQuorum bool     `json:"abstention_counts_toward_quorum"`
	VetoRoles                    []string `json:"veto_roles"`
	FormalObjectionEffect        string   `json:"formal_objection_effect"`
	TieResolution                string   `json:"tie_resolution"`
	QuorumFailure                string   `json:"quorum_failure"`
	RevocationPolicy             string   `json:"revocation_policy"`
	EvidenceChangePolicy         string   `json:"evidence_change_policy"`
}

type Ballot struct {
	BallotID         string  `json:"ballot_id"`
	ProposalID       string  `json:"proposal_id"`
	SnapshotID       string  `json:"snapshot_id"`
	EvidenceManifest *string `json:"evidence_manifest"`
	Voter            string  `json:"voter"`
	Position         string  `json:"position"`
	Sequence         int     `json:"sequence"`
	IssuedAt         string  `json:"issued_at"`
}

type Objection struct {
	ObjectionID string `json:"objection_id"`
	ProposalID  string `json:"proposal_id"`
	Objector    string `json:"objector"`
	Severity    string `json:"severity"`
}

type Revocation struct {
	RevocationID string `json:"revocation_id"`
	MemberID     string `json:"member_id"`
	EffectiveAt  string `json:"effective_at"`
}

type Input struct {
	Name                   string       `json:"name"`
	ProposalID             string       `json:"proposal_id"`
	SnapshotID             string       `json:"snapshot_id"`
	Members                []Member     `json:"members"`
	Rule                   Rule         `json:"rule"`
	Ballots                []Ballot     `json:"ballots"`
	Objections             []Objection  `json:"objections"`
	Revocations            []Revocation `json:"revocations"`
	ActiveEvidenceManifest *string      `json:"active_evidence_manifest"`
	ClosingTime            string       `json:"closing_time"`
	ExpectedOutcome        string       `json:"expected_outcome"`
}

type Issue struct {
	Code     string `json:"code"`
	ObjectID string `json:"object_id"`
}

type Tally struct {
	Abstain int `json:"abstain"`
	Approve int `json:"approve"`
	Defer   int `json:"defer"`
	Reject  int `json:"reject"`
}

type Output struct {
	BlockingObjections []string `json:"blocking_objections"`
	BlockingVetoes     []string `json:"blocking_vetoes"`
	InputRoot          string   `json:"input_root"`
	Issues             []Issue  `json:"issues"`
	Outcome            string   `json:"outcome"`
	ProposalID         string   `json:"proposal_id"`
	SnapshotID         string   `json:"snapshot_id"`
	Tally              Tally    `json:"tally"`
	ValidBallotIDs     []string `json:"valid_ballot_ids"`
	ValidObjectionIDs  []string `json:"valid_objection_ids"`
}

type Normalized struct {
	ActiveEvidenceManifest *string      `json:"active_evidence_manifest"`
	Ballots                []Ballot     `json:"ballots"`
	Members                []Member     `json:"members"`
	Objections             []Objection  `json:"objections"`
	ProposalID             string       `json:"proposal_id"`
	Revocations            []Revocation `json:"revocations"`
	Rule                   Rule         `json:"rule"`
	SnapshotID             string       `json:"snapshot_id"`
}

func contains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}

func issue(code, objectID string) Issue {
	return Issue{Code: code, ObjectID: objectID}
}

func ptrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func resolve(in Input) Output {
	memberMap := map[string]Member{}
	for _, m := range in.Members {
		memberMap[m.MemberID] = m
	}

	revoked := map[string]Revocation{}
	sort.Slice(in.Revocations, func(i, j int) bool {
		if in.Revocations[i].MemberID != in.Revocations[j].MemberID {
			return in.Revocations[i].MemberID < in.Revocations[j].MemberID
		}
		if in.Revocations[i].EffectiveAt != in.Revocations[j].EffectiveAt {
			return in.Revocations[i].EffectiveAt < in.Revocations[j].EffectiveAt
		}
		return in.Revocations[i].RevocationID < in.Revocations[j].RevocationID
	})
	for _, r := range in.Revocations {
		if r.EffectiveAt <= in.ClosingTime {
			revoked[r.MemberID] = r
		}
	}

	grouped := map[string][]Ballot{}
	issues := []Issue{}

	for _, b := range in.Ballots {
		m, ok := memberMap[b.Voter]
		_ = m
		if !ok {
			issues = append(issues, issue("NON_MEMBER_VOTE", b.BallotID))
			continue
		}
		if b.ProposalID != in.ProposalID {
			issues = append(issues, issue("WRONG_PROPOSAL", b.BallotID))
			continue
		}
		if b.SnapshotID != in.SnapshotID {
			issues = append(issues, issue("WRONG_SNAPSHOT", b.BallotID))
			continue
		}
		if !contains([]string{"approve", "reject", "abstain", "defer"}, b.Position) {
			issues = append(issues, issue("INVALID_POSITION", b.BallotID))
			continue
		}

		if r, ok := revoked[b.Voter]; ok {
			before := b.IssuedAt < r.EffectiveAt
			switch in.Rule.RevocationPolicy {
			case "vote_invalidated":
				issues = append(issues, issue("MEMBER_REVOKED", b.BallotID))
				continue
			case "vote_remains_valid":
				if !before {
					issues = append(issues, issue("VOTE_AFTER_REVOCATION", b.BallotID))
					continue
				}
			case "human_review_required":
				issues = append(issues, issue("REVOCATION_REQUIRES_REVIEW", b.BallotID))
				continue
			}
		}

		if in.ActiveEvidenceManifest != nil && !ptrEqual(b.EvidenceManifest, in.ActiveEvidenceManifest) {
			switch in.Rule.EvidenceChangePolicy {
			case "reconfirmation_required":
				issues = append(issues, issue("STALE_EVIDENCE_MANIFEST", b.BallotID))
				continue
			case "human_review_required":
				issues = append(issues, issue("EVIDENCE_CHANGE_REQUIRES_REVIEW", b.BallotID))
				continue
			}
		}
		grouped[b.Voter] = append(grouped[b.Voter], b)
	}

	validBallots := []Ballot{}
	for voter, ballots := range grouped {
		seqPositions := map[int]map[string]bool{}
		for _, b := range ballots {
			if seqPositions[b.Sequence] == nil {
				seqPositions[b.Sequence] = map[string]bool{}
			}
			seqPositions[b.Sequence][b.Position] = true
		}
		equivocation := false
		for _, positions := range seqPositions {
			if len(positions) > 1 {
				equivocation = true
			}
		}
		if equivocation {
			issues = append(issues, issue("EQUIVOCATION", voter))
			continue
		}
		sort.Slice(ballots, func(i, j int) bool {
			if ballots[i].Sequence != ballots[j].Sequence {
				return ballots[i].Sequence < ballots[j].Sequence
			}
			if ballots[i].IssuedAt != ballots[j].IssuedAt {
				return ballots[i].IssuedAt < ballots[j].IssuedAt
			}
			return ballots[i].BallotID < ballots[j].BallotID
		})
		validBallots = append(validBallots, ballots[len(ballots)-1])
	}

	validObjections := []Objection{}
	for _, o := range in.Objections {
		if _, ok := memberMap[o.Objector]; !ok {
			issues = append(issues, issue("NON_MEMBER_OBJECTION", o.ObjectionID))
			continue
		}
		if o.ProposalID != in.ProposalID {
			issues = append(issues, issue("WRONG_PROPOSAL", o.ObjectionID))
			continue
		}
		validObjections = append(validObjections, o)
	}

	sort.Slice(validBallots, func(i, j int) bool { return validBallots[i].BallotID < validBallots[j].BallotID })
	sort.Slice(validObjections, func(i, j int) bool { return validObjections[i].ObjectionID < validObjections[j].ObjectionID })
	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Code != issues[j].Code {
			return issues[i].Code < issues[j].Code
		}
		return issues[i].ObjectID < issues[j].ObjectID
	})

	tally := Tally{}
	quorumCount := 0
	for _, b := range validBallots {
		weight := memberMap[b.Voter].Weight
		if weight == 0 {
			weight = 1
		}
		switch b.Position {
		case "approve":
			tally.Approve += weight
		case "reject":
			tally.Reject += weight
		case "abstain":
			tally.Abstain += weight
		case "defer":
			tally.Defer += weight
		}
		if in.Rule.AbstentionCountsTowardQuorum || b.Position != "abstain" {
			quorumCount++
		}
	}

	vetoes := []string{}
	for _, b := range validBallots {
		if b.Position == "reject" && intersects(memberMap[b.Voter].Roles, in.Rule.VetoRoles) {
			vetoes = append(vetoes, b.BallotID)
		}
	}
	sort.Strings(vetoes)

	blocking := []string{}
	for _, o := range validObjections {
		if o.Severity == "blocking" {
			blocking = append(blocking, o.ObjectionID)
		}
	}
	sort.Strings(blocking)

	review := false
	for _, is := range issues {
		if is.Code == "REVOCATION_REQUIRES_REVIEW" || is.Code == "EVIDENCE_CHANGE_REQUIRES_REVIEW" {
			review = true
		}
	}

	outcome := ""
	if review {
		outcome = "escalated"
	} else if len(vetoes) > 0 {
		outcome = "blocked"
	} else if len(blocking) > 0 {
		switch in.Rule.FormalObjectionEffect {
		case "block":
			outcome = "blocked"
		case "reject":
			outcome = "rejected"
		default:
			outcome = "escalated"
		}
	} else if quorumCount < in.Rule.QuorumMinimum {
		if in.Rule.QuorumFailure == "" {
			outcome = "inconclusive"
		} else {
			outcome = in.Rule.QuorumFailure
		}
	} else if tally.Approve > tally.Reject {
		outcome = "approved"
	} else if tally.Approve == tally.Reject {
		switch in.Rule.TieResolution {
		case "human_escalation":
			outcome = "escalated"
		case "reject":
			outcome = "rejected"
		default:
			outcome = "inconclusive"
		}
	} else {
		outcome = "rejected"
	}

	sort.Slice(in.Members, func(i, j int) bool { return in.Members[i].MemberID < in.Members[j].MemberID })
	normalized := Normalized{
		ActiveEvidenceManifest: in.ActiveEvidenceManifest,
		Ballots:                validBallots,
		Members:                in.Members,
		Objections:             validObjections,
		ProposalID:             in.ProposalID,
		Revocations:            in.Revocations,
		Rule:                   in.Rule,
		SnapshotID:             in.SnapshotID,
	}
	rawNormalized, _ := json.Marshal(normalized)
	var canonicalNormalized any
	if err := json.Unmarshal(rawNormalized, &canonicalNormalized); err != nil {
		panic(err)
	}
	normBytes, _ := json.Marshal(canonicalNormalized)
	sum := sha256.Sum256(normBytes)

	validBallotIDs := []string{}
	for _, b := range validBallots {
		validBallotIDs = append(validBallotIDs, b.BallotID)
	}
	validObjectionIDs := []string{}
	for _, o := range validObjections {
		validObjectionIDs = append(validObjectionIDs, o.ObjectionID)
	}

	return Output{
		BlockingObjections: blocking,
		BlockingVetoes:     vetoes,
		InputRoot:          "sha256:" + hex.EncodeToString(sum[:]),
		Issues:             issues,
		Outcome:            outcome,
		ProposalID:         in.ProposalID,
		SnapshotID:         in.SnapshotID,
		Tally:              tally,
		ValidBallotIDs:     validBallotIDs,
		ValidObjectionIDs:  validObjectionIDs,
	}
}

func resolveFile(inputPath, outputPath string) {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		panic(err)
	}
	var input Input
	if err := json.Unmarshal(raw, &input); err != nil {
		panic(err)
	}
	encoded, err := json.Marshal(resolve(input))
	if err != nil {
		panic(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(outputPath, encoded, 0644); err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: agp-resolver INPUT.json|INPUT_DIR OUTPUT.json|OUTPUT_DIR")
		os.Exit(2)
	}
	info, err := os.Stat(os.Args[1])
	if err != nil {
		panic(err)
	}
	if info.IsDir() {
		if err := os.MkdirAll(os.Args[2], 0755); err != nil {
			panic(err)
		}
		entries, err := os.ReadDir(os.Args[1])
		if err != nil {
			panic(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			resolveFile(filepath.Join(os.Args[1], entry.Name()), filepath.Join(os.Args[2], entry.Name()))
		}
		return
	}
	resolveFile(os.Args[1], os.Args[2])
}
