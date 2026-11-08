use std::{
    collections::{HashMap, HashSet},
    fmt,
};

use crate::vm::{
    bytecode::Phase,
    encoders::{identity, Encode},
};

#[derive(Clone)]
struct Snapshot {
    phase: Phase,
    operations: Vec<(usize, String)>,
}

impl Snapshot {
    fn new(phase: Phase, operations: &[Box<dyn Encode>]) -> Self {
        let mut flattened = Vec::new();

        for operation in operations {
            Self::flatten(&mut flattened, operation, 0);
        }

        Self {
            phase,
            operations: flattened,
        }
    }

    fn flatten(flattened: &mut Vec<(usize, String)>, operation: &Box<dyn Encode>, depth: usize) {
        if let Some(children) = operation.children_ref() {
            flattened.push((
                identity(operation),
                format!("{}{}", "  ".repeat(depth), operation.name()).to_string(),
            ));

            for child in children {
                Self::flatten(flattened, child, depth + 1);
            }
        } else {
            flattened.push((
                identity(operation),
                format!("{}{}", "  ".repeat(depth), operation).to_string(),
            ));
        }
    }
}

#[derive(Clone)]
pub struct Snapshots {
    snapshots: Vec<Snapshot>,
}

impl Snapshots {
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
        }
    }

    pub fn record(&mut self, phase: Phase, operations: &[Box<dyn Encode>]) {
        self.snapshots.push(Snapshot::new(phase, operations));
    }
}

impl Snapshots {
    fn traces(&self) -> HashMap<usize, (Option<usize>, String)> {
        let mut traces = HashMap::new();
        let mut previous = HashMap::new();
        let mut closing = HashMap::new();

        for (index, snapshot) in self.snapshots.iter().enumerate() {
            for (position, (address, current)) in snapshot.operations.iter().enumerate() {
                let entry = traces.entry(*address).or_insert_with(|| {
                    let original = if index == 0 { Some(position) } else { None };
                    (original, String::new())
                });

                match previous.get(address) {
                    None => {
                        if index != 0 {
                            entry.1.extend(letter(snapshot.phase));
                        }
                    }
                    Some(prior) if *prior != current.as_str() => {
                        entry.1.extend(letter(snapshot.phase));
                    }
                    _ => {}
                }

                previous.insert(*address, current.as_str());
                closing.insert(*address, index);
            }
        }

        for (address, index) in closing {
            let remover = index + 1;
            if remover < self.snapshots.len() {
                if let Some((_, markers)) = traces.get_mut(&address) {
                    markers.extend(letter(self.snapshots[remover].phase));
                }
            }
        }

        traces
    }

    fn before(&self, remover: usize, address: usize) -> Option<usize> {
        if remover == 0 {
            return None;
        }

        self.snapshots[remover - 1]
            .operations
            .iter()
            .position(|(other, _)| *other == address)
    }

    fn born(&self, remover: usize) -> HashSet<usize> {
        if remover >= self.snapshots.len() {
            return HashSet::new();
        }

        let mut seen = HashSet::new();

        for snapshot in &self.snapshots[..remover] {
            for (address, _) in &snapshot.operations {
                seen.insert(*address);
            }
        }

        self.snapshots[remover]
            .operations
            .iter()
            .map(|(address, _)| *address)
            .filter(|address| !seen.contains(address))
            .collect::<HashSet<usize>>()
    }
}

fn letter(phase: Phase) -> [char; 2] {
    let mut chars = phase.identifier().chars();
    [
        chars.next().unwrap().to_ascii_uppercase(),
        chars.next().unwrap().to_ascii_uppercase(),
    ]
}

impl fmt::Display for Snapshots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let last = self.snapshots.last().unwrap();
        let surviving = last
            .operations
            .iter()
            .map(|(address, _)| *address)
            .collect::<HashSet<usize>>();

        let traces = self.traces();

        let width = traces
            .values()
            .map(|(_, markers)| markers.len())
            .max()
            .unwrap_or(0);

        let render = |original: Option<usize>, markers: &str, display: &str| {
            let original = match original {
                Some(value) => format!("{:>3}", value).to_string(),
                None => "   ".to_string(),
            };
            let display = display.replace('\n', "\n         ");
            format!("{} {:<width$} {}", original, markers, display).to_string()
        };

        let mut lines = last
            .operations
            .iter()
            .map(|(target, display)| {
                let (original, markers) =
                    traces.get(target).cloned().unwrap_or((None, String::new()));
                render(original, &markers, display)
            })
            .collect::<Vec<String>>();

        let mut latest = HashMap::new();

        for (index, snapshot) in self.snapshots.iter().enumerate() {
            for (position, (address, content)) in snapshot.operations.iter().enumerate() {
                latest.insert(*address, (index, position, content.clone()));
            }
        }

        let mut removed = latest
            .into_iter()
            .filter(|(address, _)| !surviving.contains(address))
            .filter_map(|(address, (index, position, content))| {
                let remover = index + 1;

                (remover < self.snapshots.len()).then_some((remover, position, address, content))
            })
            .collect::<Vec<(usize, usize, usize, String)>>();

        removed.sort_by_key(|(remover, position, _, _)| (*remover, *position));

        let mut cache = HashMap::new();

        for (remover, position, address, content) in &removed {
            let before = self.before(*remover, *address);

            let born = cache.entry(*remover).or_insert_with(|| self.born(*remover));

            if before == Some(*position) && !born.is_empty() {
                continue;
            }

            let (original, markers) = traces
                .get(address)
                .cloned()
                .unwrap_or((None, String::new()));

            lines.push(render(original, &markers, content));
        }

        write!(f, "{}", lines.join("\n"))
    }
}
