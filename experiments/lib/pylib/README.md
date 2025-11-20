# Cost Model for PreserveNone Optimization

This document defines the mathematical model used to evaluate functions for the `PreserveNone` calling convention.

## 1. Definitions

| Variable | Description |
| :--- | :--- |
| $C$ | The **callee** function being evaluated. |
| $R_C$ | The set of **Callee-Saved Registers** (CSRs) currently saved by $C$. |
| $N_{R,C}$ | The count of CSRs saved/restored by $C$. |
| $E_C$ | The **entry count** (dynamic execution count) of function $C$. |
| $\mathcal{U}_C$ | The set of **unique caller functions** calling $C$ (where caller $\neq$ callee). |
| $\mathcal{C}_S$ | The set of all **call sites** where $C$ is called. |
| $A_i$ | The **caller** function for an individual call site $S_i$. |
| $N_{R,A}$ | The count of CSRs saved/restored by caller $A$. |
| $E_A$ | The **entry count** of the caller $A$. |
| $M_{S_i}$ | The **MBB (Machine Basic Block) count** for the block containing call site $S_i$. |
| $L_{S_i}$ | The set of **live CSRs** at call site $S_i$. |
| $K_{ops}$ | The instruction cost factor for a save/restore pair (Push + Pop), defined as **2**. |
| $N_{max}$ | The maximum number of available CSRs (x86-64), defined as **6**. |

---

## 2. Dynamic Benefit ($\Delta_{Dyn}$)

The dynamic benefit represents the reduction in total executed instructions. It is calculated as the savings within the callee minus the overhead added to callers and call sites.

The factor of **2** represents the removal or addition of the `PUSH` (Prologue) and `POP` (Epilogue) instruction pair.

$$
\Delta_{Dyn}(C) = \underbrace{(2 \cdot N_{R,C} \cdot E_C)}_{\text{Callee Savings}} 
- \underbrace{\sum_{A \in \mathcal{U}_C} \left( 2 \cdot (6 - N_{R,A}) \cdot E_A \right)}_{\text{Caller Prologue/Epilogue Penalty}} 
- \underbrace{\sum_{S_i \in \mathcal{C}_S} \left( 2 \cdot |L_{S_i} \cap R_C| \cdot M_{S_i} \right)}_{\text{Call Site Spill Penalty}}
$$

### Term Breakdown
1.  **Callee Savings:** The instructions saved by removing `PUSH`/`POP` from the candidate function $C$.
2.  **Caller Prologue/Epilogue Penalty:** The cost incurred by callers ($A$) which must now save additional CSRs in their own prologues/epilogues to compensate for $C$ not preserving them.
3.  **Call Site Spill Penalty:** The cost of saving specific registers that are live across the call site ($S_i$) and were previously preserved by $C$ ($R_C$), multiplied by the execution frequency of that block ($M_{S_i}$).

---

## 3. Static Cost ($\Delta_{Stat}$)

The static cost represents the change in binary size (instruction count). A **negative** value indicates a reduction in binary size (Benefit), while a **positive** value indicates code bloat (Cost).

$$
\Delta_{Stat}(C) = \underbrace{- (2 \cdot N_{R,C})}_{\text{Callee Size Reduction}} 
+ \underbrace{\sum_{A \in \mathcal{U}_C} \left( 2 \cdot (6 - N_{R,A}) \right)}_{\text{Caller Prologue/Epilogue Bloat}} 
+ \underbrace{\sum_{S_i \in \mathcal{C}_S} \left( 2 \cdot |L_{S_i} \cap R_C| \right)}_{\text{Call Site Spill Bloat}}
$$

### Term Breakdown
1.  **Callee Size Reduction:** The removal of `PUSH`/`POP` instructions from $C$.
2.  **Caller Prologue/Epilogue Bloat:** The addition of `PUSH`/`POP` instructions to the callers' entry/exit points.
3.  **Call Site Spill Bloat:** The addition of spill/reload instructions around specific call sites.

---

## 4. Candidate Determination Thresholds

A function $C$ is determined to be a valid `PreserveNone` candidate if it provides a strictly positive dynamic benefit (performance improvement) while strictly decreasing static cost (code size reduction).

$$
C \in \text{Candidates} \iff \Delta_{Dyn}(C) > 0 \quad \land \quad \Delta_{Stat}(C) < 0
$$

*Note: Since $\Delta_{Stat}$ represents the net change in size, we require it to be less than 0 to ensure no code bloat occurs.*