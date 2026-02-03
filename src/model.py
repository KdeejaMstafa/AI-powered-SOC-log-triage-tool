from transformers import AutoTokenizer, AutoModelForCausalLM
import torch


def load_model():
    model_name = "Qwen/Qwen2.5-1.5B-Instruct"

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.float32,
        device_map="auto"
    )

    return tokenizer, model


def local_llm(tokenizer, model, prompt):
    formatted = (
        "<|im_start|>system\n"
        "You are a SOC analyst assistant. You must identify the correct MITRE ATT&CK technique based on the event.\n"
        "<|im_end|>\n"
        "<|im_start|>user\n"
        f"{prompt}\n"
        "<|im_end|>\n"
        "<|im_start|>assistant\n"
    )

    inputs = tokenizer(formatted, return_tensors="pt").to(model.device)
    outputs = model.generate(
        **inputs,
        max_new_tokens=300,
        temperature=0.2,
        do_sample=False
    )

    text = tokenizer.decode(outputs[0], skip_special_tokens=True)

    if "<|im_start|>assistant" in text:
        text = text.split("<|im_start|>assistant")[-1].strip()

    return text