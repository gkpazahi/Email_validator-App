# necessary modules
from email_validator import *
import argparse

def main() -> None:
    """Main function demonstrating the enhanced validator."""
    parser = argparse.ArgumentParser(
        description="Enhanced Email Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --emails "test@example.com user@gmail.com"
  %(prog)s --file emails.txt --format json --output results.json
  %(prog)s --no-parallel  # Disable parallel processing
        """
    )
    
    parser.add_argument(
        "--emails", 
        nargs="+", 
        help="Email addresses to validate (space separated)"
    )
    parser.add_argument(
        "--file", 
        type=argparse.FileType('r'),
        help="File containing emails (one per line)"
    )
    parser.add_argument(
        "--parallel", 
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use parallel processing (default: True)"
    )
    parser.add_argument(
        "--format", 
        choices=["text", "json", "csv"], 
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--output", 
        help="Output file (default: print to console)"
    )
    
    args = parser.parse_args()
    
    # Collect emails
    emails: List[str] = []
    
    if args.emails:
        emails.extend(args.emails)
    
    if args.file:
        with args.file as f:
            file_emails = [line.strip() for line in f if line.strip()]
            emails.extend(file_emails)
    
    if not emails:
        # Interactive mode
        input_str = input("Enter emails (space separated): ").strip()
        if input_str:
            emails = [e.strip() for e in input_str.split() if e.strip()]
        else:
            print("No emails provided. Exiting.")
            return
    
    # Initialize validator
    validator = EnhancedEmailValidator(
        cache_ttl=300,
        dns_timeout=5,
        max_workers=10,
        rate_limit_delay=0.05
    )
    
    # Update local domains if needed in runtime
    input_domains_str = input("Enter your new domains separated by space: ")
    new_local_domains = set([d.strip() for d in input_domains_str.split() if d.strip()])
    validator.local_domains.update(new_local_domains)
    
    # Perform validation
    print(f"\nValidating {len(emails)} email(s)...")
    results = validator.validate_bulk_emails(emails, parallel=args.parallel)
    
    # Generate report
    try:
        report = validator.generate_report(results, format=args.format)
    except ValueError as e:
        print(f"Error generating report: {e}")
        return
    
    # Output results
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Report saved to: {args.output}")
        
        # Also save full results as JSON
        json_file = args.output.replace('.txt', '.json').replace('.csv', '.json')
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"Full results saved to: {json_file}")
    else:
        print("\n" + report)
    
    # Show cache statistics
    cache_stats = validator.get_cache_stats()
    print(f"\nCache Statistics:")
    print(f"  Active entries: {cache_stats['active_entries']}")
    print(f"  Expired entries: {cache_stats['expired_entries']}")
    print(f"  Total entries: {cache_stats['total_entries']}")

# Run main function
if __name__ == "__main__":
    main()