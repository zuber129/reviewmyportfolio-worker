"""
Extended parsing methods for insurance, bonds, gold, and alternative assets.
These methods are used by NSDLCASParser to extract non-equity/MF holdings.
"""

import re
from typing import List, Optional
from decimal import Decimal

import structlog
from app.domain.schemas import Holding

logger = structlog.get_logger()


async def parse_insurance_holdings(text: str, patterns: dict) -> List[Holding]:
    """Parse insurance holdings from text section"""
    holdings: List[Holding] = []
    lines = text.split("\n")
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Look for policy number
        policy_match = patterns["policy_number"].search(line)
        if policy_match:
            policy_number = policy_match.group(1)
            
            # Extract policy name (usually on same or previous line)
            policy_name = ""
            for j in range(max(0, i-1), min(i+2, len(lines))):
                if "insurance" in lines[j].lower() or "policy" in lines[j].lower():
                    policy_name = lines[j].strip()
                    # Remove policy number from name if present
                    policy_name = patterns["policy_number"].sub("", policy_name).strip()
                    break
            
            # Extract sum assured
            sum_assured = 0.0
            sum_assured_match = patterns["sum_assured"].search(" ".join(lines[i:i+5]))
            if sum_assured_match:
                sum_assured = float(sum_assured_match.group(1).replace(",", ""))
            
            # Extract premium
            premium = 0.0
            premium_match = patterns["premium"].search(" ".join(lines[i:i+5]))
            if premium_match:
                premium = float(premium_match.group(1).replace(",", ""))
            
            # Extract maturity date
            maturity_date = None
            maturity_match = patterns["maturity_date"].search(" ".join(lines[i:i+5]))
            if maturity_match:
                maturity_date = maturity_match.group(1)
            
            # Extract current value (for ULIPs and investment-linked policies)
            value = 0.0
            value_match = patterns["value"].search(" ".join(lines[i:i+5]))
            if value_match:
                value = float(value_match.group(1).replace(",", ""))
            
            # For pure insurance, use sum assured as value; for ULIPs use current value
            current_value = value if value > 0 else sum_assured
            
            if current_value > 0:
                holding = Holding(
                    symbol=policy_number[:10] if len(policy_number) > 10 else policy_number,
                    name=policy_name or f"Insurance Policy {policy_number}",
                    quantity=1.0,  # Insurance policies are counted as 1 unit
                    avg_price=premium if premium > 0 else current_value,
                    current_price=current_value,
                    current_value=current_value,
                    percentage=0,
                    asset_type="insurance",
                    policy_number=policy_number,
                    sum_assured=sum_assured if sum_assured > 0 else None,
                    premium_amount=premium if premium > 0 else None,
                    maturity_date=maturity_date,
                )
                holdings.append(holding)
                logger.info("insurance_holding_extracted", policy_number=policy_number, value=current_value)
        
        i += 1
    
    return holdings


async def parse_bond_holdings(text: str, patterns: dict) -> List[Holding]:
    """Parse bond and debt instrument holdings from text section"""
    holdings: List[Holding] = []
    lines = text.split("\n")
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Look for ISIN pattern (bonds have specific ISIN formats)
        isin_match = patterns["isin"].search(line)
        if isin_match:
            isin = isin_match.group(1)
            
            # Extract bond name
            bond_name = ""
            for j in range(max(0, i-1), min(i+3, len(lines))):
                if "bond" in lines[j].lower() or "debenture" in lines[j].lower() or "g-sec" in lines[j].lower():
                    bond_name = lines[j].strip()
                    bond_name = patterns["isin"].sub("", bond_name).strip()
                    break
            
            # Extract face value
            face_value = 0.0
            face_value_match = re.search(r"(?:Face\s+Value|FV)[\s:]*₹?\s*([\d,]+\.?\d*)", " ".join(lines[i:i+3]), re.IGNORECASE)
            if face_value_match:
                face_value = float(face_value_match.group(1).replace(",", ""))
            
            # Extract quantity
            quantity = 0.0
            quantity_match = patterns["quantity"].search(" ".join(lines[i:i+3]))
            if quantity_match:
                quantity = float(quantity_match.group(1).replace(",", ""))
            
            # Extract current value
            value = 0.0
            value_match = patterns["value"].search(" ".join(lines[i:i+3]))
            if value_match:
                value = float(value_match.group(1).replace(",", ""))
            
            # Extract coupon rate
            coupon_rate = None
            coupon_match = patterns["coupon_rate"].search(" ".join(lines[i:i+3]))
            if coupon_match:
                coupon_rate = float(coupon_match.group(1))
            
            # Extract credit rating
            credit_rating = None
            rating_match = patterns["credit_rating"].search(" ".join(lines[i:i+3]))
            if rating_match:
                credit_rating = rating_match.group(1)
            
            # Extract maturity date
            maturity_date = None
            maturity_match = patterns["maturity_date"].search(" ".join(lines[i:i+3]))
            if maturity_match:
                maturity_date = maturity_match.group(1)
            
            if quantity > 0 and value > 0:
                holding = Holding(
                    symbol=isin[:8],
                    name=bond_name or isin,
                    quantity=quantity,
                    avg_price=value / quantity if quantity > 0 else 0,
                    current_price=value / quantity if quantity > 0 else 0,
                    current_value=value,
                    percentage=0,
                    isin=isin,
                    asset_type="bond",
                    face_value=face_value if face_value > 0 else None,
                    coupon_rate=coupon_rate,
                    credit_rating=credit_rating,
                    maturity_date=maturity_date,
                )
                holdings.append(holding)
                logger.info("bond_holding_extracted", isin=isin, value=value)
        
        i += 1
    
    return holdings


async def parse_gold_holdings(text: str, patterns: dict) -> List[Holding]:
    """Parse gold holdings (SGBs, Gold ETFs) from text section"""
    holdings: List[Holding] = []
    lines = text.split("\n")
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Look for ISIN or gold-specific patterns
        isin_match = patterns["isin"].search(line)
        if isin_match or "sgb" in line.lower() or "gold" in line.lower():
            isin = isin_match.group(1) if isin_match else ""
            
            # Extract gold product name
            gold_name = ""
            for j in range(max(0, i-1), min(i+3, len(lines))):
                if "gold" in lines[j].lower() or "sgb" in lines[j].lower():
                    gold_name = lines[j].strip()
                    if isin:
                        gold_name = patterns["isin"].sub("", gold_name).strip()
                    break
            
            # Extract quantity (grams or units)
            quantity = 0.0
            quantity_match = re.search(r"([\d,]+\.?\d*)\s*(?:grams?|gms?|units?)", " ".join(lines[i:i+3]), re.IGNORECASE)
            if quantity_match:
                quantity = float(quantity_match.group(1).replace(",", ""))
            
            # Extract current value
            value = 0.0
            value_match = patterns["value"].search(" ".join(lines[i:i+3]))
            if value_match:
                value = float(value_match.group(1).replace(",", ""))
            
            # Extract maturity date (for SGBs)
            maturity_date = None
            maturity_match = patterns["maturity_date"].search(" ".join(lines[i:i+3]))
            if maturity_match:
                maturity_date = maturity_match.group(1)
            
            if quantity > 0 and value > 0:
                # Determine if it's SGB or Gold ETF
                asset_type = "sgb" if "sgb" in gold_name.lower() or "sovereign" in gold_name.lower() else "gold_etf"
                
                holding = Holding(
                    symbol=isin[:8] if isin else "GOLD",
                    name=gold_name or "Gold Investment",
                    quantity=quantity,
                    avg_price=value / quantity if quantity > 0 else 0,
                    current_price=value / quantity if quantity > 0 else 0,
                    current_value=value,
                    percentage=0,
                    isin=isin if isin else None,
                    asset_type=asset_type,
                    maturity_date=maturity_date,
                )
                holdings.append(holding)
                logger.info("gold_holding_extracted", type=asset_type, value=value)
        
        i += 1
    
    return holdings


async def parse_alternative_holdings(text: str, patterns: dict, asset_type: str) -> List[Holding]:
    """Parse alternative investment holdings (REITs, InvITs) from text section"""
    holdings: List[Holding] = []
    lines = text.split("\n")
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Look for ISIN pattern
        isin_match = patterns["isin"].search(line)
        if isin_match:
            isin = isin_match.group(1)
            
            # Extract name
            name = ""
            for j in range(max(0, i-1), min(i+3, len(lines))):
                if asset_type.lower() in lines[j].lower() or "trust" in lines[j].lower():
                    name = lines[j].strip()
                    name = patterns["isin"].sub("", name).strip()
                    break
            
            # Extract quantity
            quantity = 0.0
            quantity_match = patterns["quantity"].search(" ".join(lines[i:i+3]))
            if quantity_match:
                quantity = float(quantity_match.group(1).replace(",", ""))
            
            # Extract current value
            value = 0.0
            value_match = patterns["value"].search(" ".join(lines[i:i+3]))
            if value_match:
                value = float(value_match.group(1).replace(",", ""))
            
            if quantity > 0 and value > 0:
                holding = Holding(
                    symbol=isin[:8],
                    name=name or f"{asset_type.upper()} Investment",
                    quantity=quantity,
                    avg_price=value / quantity if quantity > 0 else 0,
                    current_price=value / quantity if quantity > 0 else 0,
                    current_value=value,
                    percentage=0,
                    isin=isin,
                    asset_type=asset_type,
                )
                holdings.append(holding)
                logger.info("alternative_holding_extracted", type=asset_type, isin=isin, value=value)
        
        i += 1
    
    return holdings


async def parse_retirement_holdings(text: str, patterns: dict, asset_type: str) -> List[Holding]:
    """Parse retirement account holdings (NPS, PPF, EPF) from text section"""
    holdings: List[Holding] = []
    lines = text.split("\n")
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Look for account number
        account_match = patterns["account_number"].search(line)
        if account_match:
            account_number = account_match.group(1)
            
            # Extract account name
            account_name = ""
            for j in range(max(0, i-1), min(i+2, len(lines))):
                if asset_type.lower() in lines[j].lower() or "pension" in lines[j].lower() or "provident" in lines[j].lower():
                    account_name = lines[j].strip()
                    account_name = patterns["account_number"].sub("", account_name).strip()
                    break
            
            # Extract current value/balance
            value = 0.0
            value_match = re.search(r"(?:Balance|Value|Amount)[\s:]*₹?\s*([\d,]+\.?\d*)", " ".join(lines[i:i+5]), re.IGNORECASE)
            if value_match:
                value = float(value_match.group(1).replace(",", ""))
            
            # Extract contribution amount (if available)
            contribution = None
            contribution_match = re.search(r"(?:Contribution|Deposit)[\s:]*₹?\s*([\d,]+\.?\d*)", " ".join(lines[i:i+5]), re.IGNORECASE)
            if contribution_match:
                contribution = float(contribution_match.group(1).replace(",", ""))
            
            if value > 0:
                holding = Holding(
                    symbol=account_number[:10] if len(account_number) > 10 else account_number,
                    name=account_name or f"{asset_type.upper()} Account",
                    quantity=1.0,  # Retirement accounts are counted as 1 unit
                    avg_price=value,
                    current_price=value,
                    current_value=value,
                    percentage=0,
                    asset_type=asset_type,
                    account_number=account_number,
                    contribution_amount=contribution,
                )
                holdings.append(holding)
                logger.info("retirement_holding_extracted", type=asset_type, account=account_number, value=value)
        
        i += 1
    
    return holdings
