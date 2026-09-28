mod format;
mod mutators;
mod scenario;

use std::collections::{ HashMap, HashSet };
use rand;
use rand::Rng;
use self::format::InputFormat;
use run::TestSize;

/// saved with each entry in the queue
/// this is used so that we don't repeat history
/// (and thus not waste any cycles)
#[derive(Default,Debug,Clone,Serialize,Deserialize)]
pub struct MutationHistory {
	finished: HashSet<u64>,
	#[serde(default)]
	scenario_hint_sequence: u64,
}

pub struct MutationScheduleConfig {
	pub skip_deterministic: bool,
	pub skip_non_deterministic: bool,
	pub independent_random: bool,
}

/// contains a list of possible mutations
pub struct MutationSchedule {
	config: MutationScheduleConfig,
	scenario_mode: bool,
	scenario_search_seed: u64,
	format: InputFormat,
	/// length of input in bytes including padding
	input_size: usize,
	///
	mutators: Vec<MutatorEntry>,
	mutator_id_to_name: HashMap<u64, String>
}

impl MutationSchedule {
	pub fn initialize(config: MutationScheduleConfig, test_size: TestSize,
	                  input: Vec<(String,u32)>, scenario_search_seed: u64) -> Self {
		let input_size = test_size.input;
		let format = InputFormat::new(input, input_size);
		let mutators = mutators::get_list();
		let mut mutator_id_to_name = HashMap::with_capacity(mutators.len());
		for mutator in &mutators {
			mutator_id_to_name.insert(mutator.id, mutator.name.clone());
		}
		// TODO: fix horrible hack!!!
		mutator_id_to_name.insert(mutators::RANDOM_BITFLIP_MUTATOR_ID, "random biflips".to_string());
		mutator_id_to_name.insert(mutators::AFL_HAVOC_MUTATOR_ID, "afl havoc".to_string());
		mutator_id_to_name.insert(mutators::RANDOM_GENERATOR_MUTATOR_ID, "random".to_string());
		mutator_id_to_name.insert(scenario::SCENARIO_MUTATOR_ID,
			"scenario upstream decision".to_string());
		let scenario_mode = std::env::var("MYFUZZ_RFUZZ_SCENARIO_MODE")
			.map(|value| value == "1").unwrap_or(false);
		MutationSchedule { config, scenario_mode, scenario_search_seed,
			format, input_size, mutators,
			mutator_id_to_name }
	}

	pub fn get_mutator(&self, history: &mut MutationHistory, inputs: &[u8],
	                   latest_feedback_buffer_id: u32) -> Option<Box<Mutator>> {
		if self.scenario_mode {
			let path = std::env::var("MYFUZZ_SCENARIO_HINT_FILE")
				.expect("scenario mode requires MYFUZZ_SCENARIO_HINT_FILE");
			let hint = scenario::ScenarioHint::from_file(&path,
				latest_feedback_buffer_id);
			if hint.sequence <= history.scenario_hint_sequence { return None; }
			history.scenario_hint_sequence = hint.sequence;
			return Some(Box::new(scenario::ScenarioDecisionMutator::create(
				inputs, hint, self.scenario_search_seed)));
		}
		if self.config.independent_random {
			let mut rng = rand::thread_rng();
			let seed : Seed = [rng.next_u32(), rng.next_u32(), rng.next_u32(), rng.next_u32()];
			let mutator = Box::new(mutators::RandomGenerator::create(inputs.len(), seed));
			Some(mutator)
		} else {
			if !self.config.skip_deterministic {
				for mutator in &self.mutators {
					assert!(mutator.deterministic, "non-deterministic mutators not suported at the moment!");
					// TODO: for non-deterministic mutators, the single hash set is not really going to work....
					if !history.finished.contains(&mutator.id) {
						history.finished.insert(mutator.id);
						return Some((mutator.create)(&self.format, inputs));
					}
				}
			}
			// hacky non-deterministic stage
			if !self.config.skip_non_deterministic {
				let mut rng = rand::thread_rng();
				let seed : Seed = [rng.next_u32(), rng.next_u32(), rng.next_u32(), rng.next_u32()];
				//let mutator = Box::new(mutators::RandomBitflipMutator::create(&self.format, inputs, seed));
				let mutator = Box::new(mutators::AflHavocMutator::create(&self.format, inputs, seed));
				return Some(mutator);
			}
			None
		}
	}

	pub fn get_name(&self, id: MutatorId) -> &str {
		&self.mutator_id_to_name[&id.id]
	}

	pub fn get_names(&self) -> Vec<(String, u64)> {
		self.mutator_id_to_name.iter().map(|(id, name)| (name.clone(), *id)).collect()
	}
}

pub fn identity(seed: &[u8]) -> Box<Mutator> {
	Box::new(mutators::IdentityMutator::create(seed))
}

pub(crate) struct MutatorEntry {
	id: u64,
	name: String,
	version: u32,
	deterministic: bool,
	create: Box<Fn(&InputFormat, &[u8]) -> Box<Mutator>>,
}

pub trait Mutator {
	/// unique id + Option<seed>
	fn id(&self) -> MutatorId;
	/// number of different mutations that can be performed for this instance
	fn max(&self) -> u32;
	/// the number of bytes that *all* mutation results have, None if the output size is variable
	fn output_size(&self) -> Option<usize>;
	/// apply mutation `ii` on input (`ii` in [0, max]) and write it to output
	fn apply(&mut self, ii: u32, output: &mut [u8]) -> usize;
}

pub(crate) type Seed = [u32; 4];

#[cfg(test)]
mod scenario_schedule_tests {
	use super::*;
	use run::TestSize;
	use serde_json::json;
	use std::fs;

	#[test]
	fn completed_parent_uses_next_feedback_hint_once() {
		let path = std::env::temp_dir().join(format!(
			"myfuzz-scenario-hint-{}-schedule.json", std::process::id()));
		let run_id = "scenario-schedule-test";
		std::env::set_var("MYFUZZ_RFUZZ_SCENARIO_MODE", "1");
		std::env::set_var("MYFUZZ_SCENARIO_HINT_FILE", &path);
		std::env::set_var("MYFUZZ_SCENARIO_RUN_ID", run_id);
		let write_hint = |sequence: u64, source: u8| {
			let doc = json!({
				"schema_version": "scenario_mutation_hint.v1",
				"run_id": run_id, "sequence": sequence,
				"latest_completed_batch": [{"run_id": run_id,
					"buffer_id": sequence - 1, "slot": 0,
					"raw_sha256": "0000000000000000000000000000000000000000000000000000000000000000"}],
				"max_completed_buffer_id": sequence - 1,
				"template": 0, "path": 0, "source": source, "energy": 1
			});
			fs::write(&path, doc.to_string()).unwrap();
		};
		write_hint(1, 0);
		let schedule = MutationSchedule::initialize(
			MutationScheduleConfig { skip_deterministic: false,
				skip_non_deterministic: false, independent_random: false },
			TestSize { coverage: 1, input: 8 },
			vec![("record".to_string(), 64)], 42);
		let mut history = MutationHistory::default();
		assert!(schedule.get_mutator(&mut history, &[0; 8], 0).is_some());
		assert!(schedule.get_mutator(&mut history, &[0; 8], 0).is_none());
		write_hint(2, 1);
		assert!(schedule.get_mutator(&mut history, &[0; 8], 1).is_some(),
			"a completed corpus parent must use a newer host feedback hint");
		assert!(schedule.get_mutator(&mut history, &[0; 8], 1).is_none());
		fs::remove_file(path).unwrap();
		std::env::remove_var("MYFUZZ_RFUZZ_SCENARIO_MODE");
		std::env::remove_var("MYFUZZ_SCENARIO_HINT_FILE");
		std::env::remove_var("MYFUZZ_SCENARIO_RUN_ID");
	}
}

#[derive(Hash,Copy,Clone,Debug,PartialEq,Eq,PartialOrd,Serialize,Deserialize)]
pub struct MutatorId {
	pub id: u64,
	seed: Option<Seed>,
}

#[derive(Copy,Clone,Debug,PartialEq,PartialOrd,Serialize,Deserialize)]
pub struct MutationInfo {
	pub mutator: MutatorId,
	pub ii: u32,
}
