"""LoRA fine-tuning of an instruction model on the VulnCodeX training split (TRL SFTTrainer).

Usage:  python finetune/train_lora.py \
            --run qwen2.5-coder-7b_cve_no_severity [--max-steps 10]
Reads:  work/finetune/data/<data>/{train,validation}.jsonl   (prepare_data.py)
Writes: work/finetune/runs/<run>/   checkpoints, final adapter (adapter/), trainer logs,
        run_config.json (every setting below), timing.json (minutes per segment, if resumed)

Each example is a prompt-completion pair (the benchmark prompt and the numbered reference answers), so
the loss covers the answer tokens only. LoRA on every linear layer of the language model; bf16;
gradient checkpointing; batches group records of similar length (shuffled in mega-batches). The validation loss on a fixed subset is computed every EVAL_STEPS steps, and
the checkpoint with the lowest validation loss is kept as the final adapter.

Resuming: a full checkpoint (adapter, optimizer, scheduler, RNG state, position in the data) is saved
every EVAL_STEPS steps. Running the same command again continues from the latest checkpoint of the run;
--fresh starts over instead. At most 100 steps (about 30 minutes) are lost after an interruption.
"""
import argparse
import json
import time
from pathlib import Path

from datasets import load_dataset
from peft import LoraConfig
from trl import SFTConfig, SFTTrainer

DATA = ROOT / 'work' / 'finetune' / 'data'
RUNS = ROOT / 'work' / 'finetune' / 'runs'
SETTINGS = {
    'model': 'Qwen/Qwen2.5-Coder-7B-Instruct',
    'data': 'cve_no_severity',
    'max_length': 6144,           # longest example is 5,662 tokens: nothing is truncated
    'epochs': 2,
    'learning_rate': 1e-4,
    'lr_scheduler': 'cosine',
    'warmup_ratio': 0.03,
    'per_device_batch': 4,
    'grad_accum': 8,              # effective batch 32 records
    'lora_r': 16,
    'lora_alpha': 32,
    'lora_dropout': 0.05,
    'eval_subset': 600,           # validation records used for the loss during training
    'eval_steps': 100,
    'seed': 0,
}


def to_prompt_completion(ex):
    return {'prompt': [ex['messages'][0]], 'completion': [ex['messages'][1]]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--run', required=True)
    ap.add_argument('--max-steps', type=int, default=-1, help='stop early (smoke test)')
    ap.add_argument('--fresh', action='store_true', help='ignore existing checkpoints and start over')
    args = ap.parse_args()
    s = SETTINGS
    out = RUNS / args.run
    out.mkdir(parents=True, exist_ok=True)
    (out / 'run_config.json').write_text(json.dumps(dict(s, max_steps=args.max_steps), indent=1) + '\n')

    files = {p: str(DATA / s['data'] / f'{p}.jsonl') for p in ('train', 'validation')}
    ds = load_dataset('json', data_files=files)
    ds = ds.map(to_prompt_completion, remove_columns=['messages'])
    val = ds['validation'].shuffle(seed=s['seed']).select(range(s['eval_subset']))

    config = SFTConfig(
        output_dir=str(out),
        num_train_epochs=s['epochs'], max_steps=args.max_steps,
        per_device_train_batch_size=s['per_device_batch'], per_device_eval_batch_size=s['per_device_batch'],
        gradient_accumulation_steps=s['grad_accum'],
        learning_rate=s['learning_rate'], lr_scheduler_type=s['lr_scheduler'], warmup_steps=s['warmup_ratio'],  # a float < 1 is a ratio
        bf16=True, gradient_checkpointing=True, max_length=s['max_length'],
        train_sampling_strategy='group_by_length',   # batches of similar length: much less padding
        completion_only_loss=True,
        eval_strategy='steps', eval_steps=s['eval_steps'], save_strategy='steps', save_steps=s['eval_steps'],
        save_total_limit=3, load_best_model_at_end=True, metric_for_best_model='eval_loss',
        logging_steps=10, report_to='none', seed=s['seed'],
        model_init_kwargs={'dtype': 'bfloat16', 'attn_implementation': 'sdpa'},
    )
    lora = LoraConfig(r=s['lora_r'], lora_alpha=s['lora_alpha'], lora_dropout=s['lora_dropout'],
                      target_modules='all-linear', task_type='CAUSAL_LM')
    trainer = SFTTrainer(model=s['model'], args=config, train_dataset=ds['train'], eval_dataset=val,
                         peft_config=lora)
    start = time.time()
    checkpoints = sorted(out.glob('checkpoint-*'), key=lambda p: int(p.name.split('-')[1]))
    resume = str(checkpoints[-1]) if checkpoints and not args.fresh else None
    print('resuming from', resume) if resume else print('starting from step 0')
    trainer.train(resume_from_checkpoint=resume)
    minutes = (time.time() - start) / 60
    trainer.save_model(str(out / 'adapter'))
    timing = json.loads((out / 'timing.json').read_text()) if (out / 'timing.json').exists() else []
    timing = timing if isinstance(timing, list) else [timing]          # one entry per (resumed) segment
    timing.append({'resumed_from': resume, 'minutes': round(minutes, 1), 'reached_step': trainer.state.global_step})
    (out / 'timing.json').write_text(json.dumps(timing, indent=1) + '\n')
    print(f'done: {trainer.state.global_step} steps in {minutes:.1f} min -> {out / "adapter"}')


if __name__ == '__main__':
    main()
