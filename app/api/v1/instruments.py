"""Instruments API endpoints for instrument search and management."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from app.api.dependencies import get_current_user
from app.domain.schemas import (
    Instrument,
    InstrumentSearchResult,
    InstrumentSymbolCreate,
    InstrumentSymbol,
)
from app.infrastructure.supabase_client import SupabaseClient

router = APIRouter()


@router.get("/search", response_model=List[InstrumentSearchResult])
async def search_instruments(
    q: str = Query(..., min_length=1, description="Search query"),
    limit: int = Query(10, ge=1, le=50, description="Maximum results"),
    supabase: SupabaseClient = Depends(),
):
    """
    Search instruments by symbol or name.
    Searches across all symbols (primary and alternate).
    """
    try:
        instruments = await supabase.search_instruments(query=q, limit=limit)
        return instruments
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@router.get("/{symbol}", response_model=Instrument)
async def get_instrument(
    symbol: str,
    supabase: SupabaseClient = Depends(),
):
    """
    Get instrument details by symbol.
    Looks up via any symbol (primary or alternate) and returns full instrument with all symbols.
    """
    try:
        instrument = await supabase.get_instrument_by_symbol(symbol)
        if not instrument:
            raise HTTPException(status_code=404, detail="Instrument not found")
        return instrument
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch instrument: {str(e)}")


@router.post("/{instrument_id}/symbols", response_model=InstrumentSymbol)
async def add_instrument_symbol(
    instrument_id: str,
    symbol_data: InstrumentSymbolCreate,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(),
):
    """
    Add a new symbol to an existing instrument.
    Requires authentication.
    """
    try:
        # Verify instrument exists
        instrument = await supabase.get_instrument_by_id(instrument_id)
        if not instrument:
            raise HTTPException(status_code=404, detail="Instrument not found")
        
        # Add the symbol
        new_symbol = await supabase.add_instrument_symbol(
            instrument_id=instrument_id,
            symbol=symbol_data.symbol,
            exchange=symbol_data.exchange,
            source=symbol_data.source,
            is_primary=symbol_data.is_primary,
        )
        return new_symbol
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add symbol: {str(e)}")


@router.delete("/symbols/{symbol_id}")
async def delete_instrument_symbol(
    symbol_id: str,
    current_user: dict = Depends(get_current_user),
    supabase: SupabaseClient = Depends(),
):
    """
    Remove a symbol from an instrument.
    Cannot delete the primary symbol.
    Requires authentication.
    """
    try:
        # Check if it's a primary symbol
        symbol = await supabase.get_instrument_symbol(symbol_id)
        if not symbol:
            raise HTTPException(status_code=404, detail="Symbol not found")
        
        if symbol.get("is_primary"):
            raise HTTPException(
                status_code=400,
                detail="Cannot delete primary symbol. Set another symbol as primary first."
            )
        
        await supabase.delete_instrument_symbol(symbol_id)
        return {"message": "Symbol deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete symbol: {str(e)}")
