class Util:
    @staticmethod
    def print_scores(func_dict):
        print("=" * 20)
        program_dynamic_score = sum([scores['dynamic'] for func, scores in func_dict.items()])
        program_static_score = sum([scores['static'] for func, scores in func_dict.items()])
        print(f"- Dynamic Score: {program_dynamic_score}")
        print(f"- Static Score: {program_static_score}")
        print("=" * 20)
