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
                format!("{}{}", "  ".repeat(depth), operation.name()),
            ));

            for child in children {
                Self::flatten(flattened, child, depth + 1);
            }
        } else {
            flattened.push((
                identity(operation),
                format!("{}{}", "  ".repeat(depth), operation),
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
    fn trace(&self, target: usize) -> (Option<usize>, String) {
        let mut original = None;
        let mut markers = String::new();
        let mut previous = None;
        let mut closing = None;

        for (index, snapshot) in self.snapshots.iter().enumerate() {
            let Some((position, (_, current))) = snapshot
                .operations
                .iter()
                .enumerate()
                .find(|(_, (other, _))| *other == target)
            else {
                continue;
            };

            match previous {
                None => {
                    if index == 0 {
                        original = Some(position);
                    } else {
                        markers.extend(letter(snapshot.phase));
                    }
                }
                Some(prior) if prior != current.as_str() => {
                    markers.extend(letter(snapshot.phase));
                }
                _ => {}
            }

            previous = Some(current.as_str());
            closing = Some(index);
        }

        if let Some(closing) = closing {
            let remover = closing + 1;

            if remover < self.snapshots.len() {
                markers.extend(letter(self.snapshots[remover].phase));
            }
        }

        (original, markers)
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

    fn born(&self, remover: usize) -> Vec<usize> {
        if remover >= self.snapshots.len() {
            return Vec::new();
        }

        let seen = |address: usize| {
            self.snapshots[..remover].iter().any(|snapshot| {
                snapshot
                    .operations
                    .iter()
                    .any(|(other, _)| *other == address)
            })
        };

        self.snapshots[remover]
            .operations
            .iter()
            .map(|(address, _)| *address)
            .filter(|&address| !seen(address))
            .collect::<Vec<usize>>()
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

        let width = self
            .snapshots
            .iter()
            .flat_map(|snapshot| {
                snapshot
                    .operations
                    .iter()
                    .map(|(target, _)| self.trace(*target).1.len())
            })
            .max()
            .unwrap_or(0);

        let render = |original: Option<usize>, markers: &str, display: &str| {
            let original = match original {
                Some(value) => format!("{:>3}", value),
                None => "   ".to_string(),
            };
            let display = display.replace('\n', "\n         ");
            format!("{} {:<width$} {}", original, markers, display)
        };

        let mut lines = last
            .operations
            .iter()
            .map(|(target, display)| {
                let (original, markers) = self.trace(*target);
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

        for (remover, position, address, content) in &removed {
            let before = self.before(*remover, *address);

            if before == Some(*position) && !self.born(*remover).is_empty() {
                continue;
            }

            let (original, markers) = self.trace(*address);
            lines.push(render(original, &markers, content));
        }

        write!(f, "{}", lines.join("\n"))
    }
}
