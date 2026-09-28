//! Scenario mode mutates upstream decision records using host coverage hints.
//! The host still validates ownership and runs the real RTL for each testcase.

use std::fs;
use serde_json;
use super::{Mutator, MutatorId};

pub const SCENARIO_MUTATOR_ID: u64 = 0x5343454e4152494f;

#[derive(Clone, Debug)]
pub struct ScenarioHint {
	pub sequence: u64,
	pub template: u8,
	pub path: u8,
	pub source: u8,
	pub energy: u32,
}

impl ScenarioHint {
	pub fn from_file(path: &str, latest_feedback_buffer_id: u32) -> Self {
		let data = fs::read_to_string(path).expect("scenario hint file missing");
		let value: serde_json::Value = serde_json::from_str(&data)
			.expect("invalid scenario hint JSON");
		assert_eq!(value["schema_version"].as_str(),
			Some("scenario_mutation_hint.v1"), "unknown scenario hint schema");
		let expected_run = std::env::var("MYFUZZ_SCENARIO_RUN_ID")
			.expect("scenario mode requires MYFUZZ_SCENARIO_RUN_ID");
		assert_eq!(value["run_id"].as_str(), Some(expected_run.as_str()),
			"scenario hint belongs to another run");
		let sequence = value["sequence"].as_u64().unwrap_or(0);
		assert!(sequence > 0,
			"scenario hint sequence is missing");
		let feedback = value["latest_completed_batch"].as_array()
			.expect("scenario hint feedback provenance is missing");
		assert!(!feedback.is_empty(),
			"scenario hint has no completed feedback");
		let host_buffer = value["max_completed_buffer_id"].as_u64()
			.expect("scenario hint completed buffer identity is missing");
		assert!(host_buffer >= latest_feedback_buffer_id as u64,
			"scenario hint feedback is stale");
		for receipt in feedback {
			assert_eq!(receipt["run_id"].as_str(), Some(expected_run.as_str()),
				"scenario hint feedback belongs to another run");
			assert!(receipt["buffer_id"].as_u64().is_some()
				&& receipt["slot"].as_u64().is_some()
				&& receipt["raw_sha256"].as_str().map_or(false, |s| s.len() == 64),
				"scenario hint feedback execution key is incomplete");
		}
		let byte = |name: &str| -> u8 {
			let number = value[name].as_u64().expect("scenario hint byte missing");
			assert!(number <= 255, "scenario hint byte outside range");
			number as u8
		};
		let energy = value["energy"].as_u64().expect("scenario hint energy missing");
		assert!((1..=1024).contains(&energy), "scenario hint energy outside range");
		ScenarioHint { sequence, template: byte("template"), path: byte("path"),
			source: byte("source"), energy: energy as u32 }
	}
}

pub struct ScenarioDecisionMutator {
	inputs: Vec<u8>,
	hint: ScenarioHint,
	search_seed: u64,
}

impl ScenarioDecisionMutator {
	pub fn create(inputs: &[u8], hint: ScenarioHint, search_seed: u64) -> Self {
		assert!(!inputs.is_empty() && inputs.len() % 8 == 0,
			"scenario input must have eight byte records");
		ScenarioDecisionMutator { inputs: inputs.to_vec(), hint, search_seed }
	}
}

impl Mutator for ScenarioDecisionMutator {
	fn id(&self) -> MutatorId { MutatorId { id: SCENARIO_MUTATOR_ID, seed: None } }
	fn max(&self) -> u32 { self.hint.energy }
	fn output_size(&self) -> Option<usize> { Some(self.inputs.len()) }
	fn apply(&mut self, ii: u32, output: &mut [u8]) -> usize {
		assert_eq!(output.len(), self.inputs.len());
		// The run seed and completed feedback epoch both affect candidates.
		// Reusing a parent after new feedback must not replay its old raw batch.
		let epoch = self.hint.sequence - 1;
		let epoch_offset = (epoch as u32).wrapping_mul(0x85ebca6b)
			^ ((epoch >> 32) as u32).wrapping_mul(0xc2b2ae35);
		let decision = ii.wrapping_add((self.search_seed as u32)
			.wrapping_mul(0x9e3779b9) ^ (self.search_seed >> 32) as u32)
			.wrapping_add(epoch_offset);
		output.copy_from_slice(&self.inputs);
		output[0] = self.hint.template;
		output[1] = self.hint.path;
		let count = output.len() / 8;
		let record = ((decision / 256) as usize % count) * 8;
		output[record + 2] = self.hint.source;
		output[record + 3] = (decision & 255) as u8;
		output[record + 7] = ((decision >> 8) & 255) as u8;
		output[record + 4] = ((decision / 16) & 255) as u8;
		output[record + 5] = if decision % 8 == 7 { 2 } else { 1 };
		output[record + 6] = ((decision / 32) & 15) as u8;
		output.len()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn hint_controls_template_path_source_and_energy() {
		let hint = ScenarioHint { sequence: 1, template: 3, path: 2, source: 1, energy: 64 };
		let mut mutator = ScenarioDecisionMutator::create(&[0u8; 16], hint, 0);
		assert_eq!(64, mutator.max());
		let mut result = [0u8; 16];
		assert_eq!(16, mutator.apply(5, &mut result));
		assert_eq!((3, 2, 1, 5, 1),
			(result[0], result[1], result[2], result[3], result[5]));
	}

	#[test]
	fn search_seed_changes_candidates_reproducibly() {
		let hint = ScenarioHint { sequence: 1, template: 0, path: 0, source: 0, energy: 64 };
		let mut first = ScenarioDecisionMutator::create(&[0u8; 16], hint.clone(), 11);
		let mut repeated = ScenarioDecisionMutator::create(&[0u8; 16], hint.clone(), 11);
		let mut different = ScenarioDecisionMutator::create(&[0u8; 16], hint, 12);
		let mut a = [0u8; 16];
		let mut b = [0u8; 16];
		let mut c = [0u8; 16];
		first.apply(5, &mut a);
		repeated.apply(5, &mut b);
		different.apply(5, &mut c);
		assert_eq!(a, b);
		assert_ne!(a, c);
	}

	#[test]
	fn newer_feedback_hint_changes_deterministic_candidates() {
		let first_hint = ScenarioHint { sequence: 1, template: 0, path: 0,
			source: 0, energy: 64 };
		let second_hint = ScenarioHint { sequence: 2, ..first_hint.clone() };
		let mut first = ScenarioDecisionMutator::create(&[0u8; 8], first_hint.clone(), 11);
		let mut repeated = ScenarioDecisionMutator::create(&[0u8; 8], first_hint, 11);
		let mut next = ScenarioDecisionMutator::create(&[0u8; 8], second_hint, 11);
		let mut a = [0u8; 8];
		let mut b = [0u8; 8];
		let mut c = [0u8; 8];
		first.apply(5, &mut a);
		repeated.apply(5, &mut b);
		next.apply(5, &mut c);
		assert_eq!(a, b);
		assert_ne!(a, c, "a new feedback epoch must explore different raw records");
	}
}
