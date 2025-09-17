import os
from firebase_admin import credentials, firestore, initialize_app

"""
Backfill script to ensure all documents in 'requests' have a 'visibility' field.
If a corresponding document exists in 'listings', prefer the visibility value from 'listings'.
Usage: python scripts/backfill_visibility.py
Make sure FIREBASE_ADMIN credentials file 'firebase_key.json' exists in project root.
"""

def main():
    cred_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'firebase_key.json')
    if not os.path.exists(cred_path):
        print(f'Credential file not found at {cred_path}. Aborting.')
        return

    cred = credentials.Certificate(cred_path)
    initialize_app(cred)
    db = firestore.client()

    total = 0
    updated = 0
    skipped = 0

    for doc in db.collection('requests').stream():
        total += 1
        data = doc.to_dict() or {}
        req_vis = data.get('visibility')

        # If there is a corresponding listings doc, prefer its visibility
        listing_doc = db.collection('listings').document(doc.id).get()
        listing_vis = None
        if listing_doc.exists:
            listing_vis = listing_doc.to_dict().get('visibility')

        # Decide what visibility to set
        new_vis = None
        if listing_vis:
            new_vis = listing_vis
        elif req_vis:
            # already present and non-empty
            skipped += 1
            continue
        else:
            new_vis = 'public'

        if new_vis:
            try:
                doc.reference.update({'visibility': new_vis})
                updated += 1
                print(f'Updated {doc.id} -> visibility={new_vis}')
            except Exception as e:
                print(f'Failed to update {doc.id}: {e}')

    print('---')
    print(f'Total processed: {total}')
    print(f'Updated: {updated}')
    print(f'Skipped (already had visibility): {skipped}')


if __name__ == '__main__':
    main()

