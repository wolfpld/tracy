# Ask Tracy Assist

[Tracy Assist](#tracyassist) is a chat window that answers questions about a capture by reading the user manual, the source cached in the capture, and the profile data itself. Ask it why a hot function is slow, and let it read the assembly and the source behind it.

Click the * Tracy Assist* button in the toolbar. The assistant talks only to a local model server (llama.cpp, LM Studio, anything OpenAI compatible), so your data stays on your machine. The [Tracy Assist setup](#serviceprovider) explains how to get one running. Expand *Settings* at the top of the chat, enter the server address, and pick a chat model and an embedding model for the user manual search. Press * Learn manual* once to build the index.

The * robot* button inside the call stack or symbol window puts whatever you are looking at into the chat, so "what does this code do?" is a complete question.

> [!TIP]
> **Tip**
>
> The assistant sees your real data, but the answers come from a language model, and models invent confident nonsense. Check its claims against the windows you already trust before acting on them.

Try asking it to explain the hottest function in your capture.
