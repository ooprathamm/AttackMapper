class RiskEngine:
    def __init__(self):
        pass

    def calculate_risk(self, services, criticality=1.0):
        score = 0
        
        score += len(services) * 5
        
        total_techniques = 0
        ignored_techniques = {"T1046"} 
        
        for service in services:
            for tech in service.get('techniques', []):
                if tech['id'] not in ignored_techniques:
                    total_techniques += 1
        
        score += total_techniques * 2
        
        score = score * criticality
        
        final_score = min(int(score), 100)
        
        return final_score, self.get_risk_level(final_score)

    def get_risk_level(self, score):
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        else:
            return "Low"
