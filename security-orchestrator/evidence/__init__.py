"""
Evidence Builder — genereert FBI-ready PDF rapporten per incident of threat actor.

Rapport secties:
  1. Cover page met classificatie en case metadata
  2. Executive summary
  3. Incident tijdlijn (chronologisch)
  4. IP intelligence (volledige enrichment data per IP)
  5. Threat actor profiel
  6. Platform bewijsmateriaal (API logs, screenshots referenties)
  7. Response acties audit trail
  8. Wettelijk kader (CFAA, EU NIS2, relevante statuten)
  9. IOC overzicht (STIX-compatibel)
  10. Chain of custody log

Exporteerbaar als PDF via dashboard knop of API endpoint.
"""
