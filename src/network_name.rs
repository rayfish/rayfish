//! Three-word network name generation (adjective-noun-noun).

use rand::RngExt;

pub const ADJECTIVES: &[&str] = &[
    "able", "aged", "airy", "amber", "arctic", "ashen", "azure", "bare", "basic", "bent", "birch",
    "black", "bland", "bleak", "blind", "bliss", "bloom", "blown", "blunt", "bold", "bone",
    "bound", "brave", "brief", "bright", "brisk", "broad", "bronze", "brown", "burnt", "calm",
    "cedar", "chill", "civic", "civil", "clean", "clear", "close", "cloud", "cold", "cool",
    "coral", "core", "crisp", "cross", "cubic", "curly", "damp", "dark", "dawn", "deep", "dense",
    "dim", "dire", "dizzy", "double", "draft", "drawn", "dried", "dull", "dusk", "dusty", "eager",
    "early", "east", "eight", "elfin", "elite", "empty", "equal", "even", "every", "extra",
    "faded", "faint", "fair", "false", "fancy", "far", "fast", "fern", "few", "final", "fine",
    "firm", "first", "fixed", "flat", "fleet", "flint", "foggy", "fond", "forge", "forth", "found",
    "fresh", "front", "frost", "full", "fuzzy", "gauze", "giant", "given", "glad", "glass",
    "gleam", "glow", "gold", "good", "grand", "grass", "grave", "gray", "great", "green", "grim",
    "grown", "half", "happy", "hard", "harsh", "hazel", "heavy", "heron", "high", "honey", "hot",
    "huge", "human", "humid", "hushy", "icy", "ideal", "idle", "inner", "ionic", "ivory", "jade",
    "jolly", "keen", "kept", "kind", "known", "lace", "large", "last", "late", "lead", "lean",
    "left", "level", "light", "lilac", "lime", "linen", "lithe", "live", "local", "lone", "long",
    "lost", "loud", "low", "lucid", "lunar", "lush", "lyric", "mad", "magic", "major", "maple",
    "meek", "mild", "mint", "misty", "mixed", "modal", "moist", "moody", "moral", "mossy", "muted",
    "naive", "named", "natal", "naval", "near", "neat", "new", "next", "nice", "noble", "north",
    "noted", "novel", "nylon", "oaken", "ocean", "odd", "olive", "only", "opal", "open", "opted",
    "orbit", "other", "outer", "oxide", "pagan", "paid", "pale", "palm", "paper", "past", "pearl",
    "penal", "petty", "pine", "pious", "pixel", "plain", "plaid", "plumb", "plush", "polar",
    "prime", "prior", "proud", "proxy", "pure", "quick", "quiet", "quill", "rapid", "rare",
    "raven", "ready", "real", "red", "reef", "regal", "rich", "rigid", "risen", "river", "rocky",
    "roman", "roomy", "rose", "rough", "round", "royal", "ruby", "rural", "rusty", "safe", "sage",
    "sandy", "satin", "sharp", "sheer", "short", "shown", "shy", "silk", "slim", "slow", "small",
    "smart", "smoky", "snowy", "soft", "solar", "solid", "sonic", "south", "spare", "spent",
    "spice", "stark", "steam", "steel", "steep", "still", "stone", "storm", "stout", "sugar",
    "sunny", "super", "sure", "sweet", "swift", "tall", "tame", "tawny", "teal", "thick", "thin",
    "third", "thorn", "tidal", "tight", "timid", "tiny", "topaz", "total", "tough", "trim", "true",
    "tulip", "twin", "ultra", "umbra", "upper", "urban", "used", "usual", "utter", "valid",
    "vapor", "vast", "veldt", "vivid", "vocal", "void", "warm", "wary", "weary", "west", "wheat",
    "white", "whole", "wide", "wild", "wiry", "wise", "witty", "woody", "world", "worth", "woven",
    "wrong", "young", "zero", "zippy",
];

pub const NOUNS_A: &[&str] = &[
    "acorn", "alder", "algae", "alloy", "alpha", "amber", "anchor", "anvil", "apex", "arbor",
    "arrow", "aspen", "atlas", "basin", "basil", "beach", "beam", "birch", "blade", "bloom",
    "bluff", "board", "bolt", "bone", "bower", "brace", "brass", "brick", "brook", "brush",
    "cairn", "cape", "cargo", "cedar", "chain", "chalk", "chess", "cider", "cinch", "claim",
    "clash", "cliff", "cloud", "clove", "coast", "comet", "conch", "coral", "crane", "crate",
    "creek", "crest", "crown", "crush", "cubic", "curve", "delta", "depot", "dew", "dial", "dock",
    "draft", "drake", "drift", "drum", "dune", "eagle", "earth", "ember", "epoch", "facet",
    "fault", "fawn", "ferry", "fetch", "fiber", "field", "firth", "flame", "flare", "flint",
    "flora", "forge", "frame", "frost", "gable", "gale", "gauge", "gears", "ghost", "glade",
    "glaze", "gleam", "globe", "gorge", "grain", "grant", "grape", "graph", "grasp", "grass",
    "gravel", "grove", "guild", "gulch", "haven", "heart", "hedge", "helix", "heron", "hinge",
    "holly", "honey", "horns", "hound", "inlet", "ivory", "jewel", "kayak", "knoll", "lager",
    "lance", "larch", "laser", "latch", "ledge", "lever", "light", "lilac", "linen", "llama",
    "locus", "lodge", "lotus", "lunar", "maple", "marsh", "mason", "matte", "mazer", "metal",
    "mirth", "mocha", "molar", "moose", "morph", "motor", "mound", "mulch", "nexus", "notch",
    "novel", "oasis", "ocean", "olive", "onion", "onset", "opera", "orbit", "otter", "oxide",
    "panda", "panel", "paper", "patch", "pearl", "pedal", "perch", "petal", "phase", "pilot",
    "pitch", "pixel", "plank", "plaza", "plume", "point", "polar", "poppy", "pouch", "press",
    "prism", "probe", "proxy", "pulse", "quail", "qualm", "query", "quilt", "quota", "radar",
    "ranch", "range", "raven", "reach", "realm", "reeds", "relay", "ridge", "rivet", "roost",
    "rover", "sable", "scale", "scone", "scope", "sedan", "shade", "shaft", "shard", "shelf",
    "shell", "shore", "shrub", "sigma", "siren", "slate", "slope", "snare", "solar", "sonic",
    "spark", "spear", "spire", "spoke", "spore", "spray", "staff", "stage", "stake", "steel",
    "stern", "stone", "storm", "stove", "sugar", "surge", "swamp", "sword", "talon", "thorn",
    "tiger", "tile", "timer", "torch", "totem", "tower", "trace", "trail", "trove", "trunk",
    "tulip", "tuner", "valve", "vapor", "vault", "venom", "verge", "verse", "vigor", "viola",
    "visor", "voice", "wedge", "wheel", "whirl", "wick", "willow", "witch", "world", "yacht",
    "yield", "young", "zebra", "zero",
];

pub const NOUNS_B: &[&str] = &[
    "arch", "badge", "bark", "basin", "bay", "bead", "bell", "berry", "bird", "blaze", "block",
    "blossom", "boat", "bolt", "book", "bow", "box", "bridge", "bud", "cairn", "camp", "cap",
    "cave", "cell", "charm", "chip", "circle", "clay", "cloth", "clover", "coal", "coin", "cone",
    "cord", "core", "court", "cow", "crab", "crow", "cup", "curl", "dale", "dam", "dart", "deer",
    "den", "dew", "disc", "door", "dove", "drum", "dust", "dye", "edge", "elm", "eye", "fall",
    "fan", "fern", "fig", "fin", "fish", "flag", "flax", "flock", "flow", "foam", "fold", "foot",
    "ford", "fork", "fort", "fox", "frog", "fur", "gap", "gate", "gem", "glow", "goat", "gull",
    "gust", "hare", "harp", "hash", "hawk", "hay", "heap", "helm", "herb", "hill", "hive", "hook",
    "horn", "hut", "isle", "ivy", "jam", "jar", "jaw", "jay", "jest", "jig", "keel", "kelp", "key",
    "kite", "knob", "knot", "lace", "lake", "lamp", "lane", "lark", "leaf", "lime", "lion", "lock",
    "log", "loom", "lore", "lynx", "mane", "map", "mark", "mast", "maze", "mesa", "mill", "mine",
    "mint", "mist", "mole", "moon", "moss", "moth", "muse", "nest", "node", "nook", "note", "oak",
    "oar", "ore", "oryx", "owl", "pace", "pact", "palm", "park", "path", "peak", "pier", "pine",
    "pipe", "plum", "pod", "pole", "pond", "port", "post", "quay", "rain", "ram", "ray", "reed",
    "reef", "ring", "rise", "road", "robe", "rock", "rod", "root", "rope", "rune", "rush", "sage",
    "sail", "salt", "sand", "seal", "seed", "silk", "snow", "soil", "soul", "span", "spur", "star",
    "stem", "step", "sun", "swan", "tarn", "teak", "tide", "tile", "toad", "tome", "tree", "vale",
    "vane", "veil", "vine", "void", "wand", "ward", "wave", "web", "well", "weld", "wren", "wing",
    "wolf", "wood", "wool", "yard", "yew", "zone", "ache", "acre", "aged", "ail", "aim", "ale",
    "aloe", "alp", "alto", "amen", "amp", "ant", "ape", "apt", "arc", "arm", "art", "ash", "ask",
    "asp", "awe", "axe", "aye", "azure", "bait", "bale", "balm", "ban", "band", "bane", "bang",
    "bard", "barn", "baste", "bath", "beam",
];

pub fn generate_name() -> String {
    let mut rng = rand::rng();
    let adj = ADJECTIVES[rng.random_range(0..ADJECTIVES.len())];
    let n1 = NOUNS_A[rng.random_range(0..NOUNS_A.len())];
    let n2 = NOUNS_B[rng.random_range(0..NOUNS_B.len())];
    format!("{adj}-{n1}-{n2}")
}

#[cfg(test)]
fn is_valid_name(name: &str) -> bool {
    let parts: Vec<&str> = name.split('-').collect();
    if parts.len() != 3 {
        return false;
    }
    parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_three_word_dash_separated() {
        let name = generate_name();
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3, "name should have 3 parts: {name}");
    }

    #[test]
    fn generate_produces_different_names() {
        let a = generate_name();
        let b = generate_name();
        // With ~1B combinations, collision on two calls is astronomically unlikely
        assert_ne!(a, b);
    }

    #[test]
    fn is_valid_accepts_generated_names() {
        let name = generate_name();
        assert!(is_valid_name(&name));
    }

    #[test]
    fn is_valid_rejects_bad_names() {
        assert!(!is_valid_name(""));
        assert!(!is_valid_name("single"));
        assert!(!is_valid_name("only-two"));
        assert!(!is_valid_name("too-many-words-here"));
        assert!(!is_valid_name("UPPER-case-name"));
    }

    #[test]
    fn word_lists_have_sufficient_size() {
        assert!(ADJECTIVES.len() >= 256);
        assert!(NOUNS_A.len() >= 256);
        assert!(NOUNS_B.len() >= 256);
    }
}
